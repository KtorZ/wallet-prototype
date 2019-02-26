{-# LANGUAGE BangPatterns        #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE TypeFamilies        #-}

module Main where

import qualified Codec.CBOR.Decoding          as CBOR
import qualified Codec.CBOR.Encoding          as CBOR
import qualified Codec.CBOR.Read              as CBOR
import qualified Codec.CBOR.Write             as CBOR
import           Control.Arrow                (first)
import           Control.DeepSeq              (NFData, deepseq)
import           Control.Monad                (forM_, void, when)
import qualified Crypto.Cipher.ChaChaPoly1305 as Poly
import           Crypto.Error                 (CryptoError (..),
                                               CryptoFailable (..))
import           Crypto.Hash                  (hash)
import           Crypto.Hash.Algorithms       (Blake2b_224, SHA3_256,
                                               SHA512 (..))
import qualified Crypto.KDF.PBKDF2            as PBKDF2
import           Data.Aeson                   (ToJSON (..))
import qualified Data.Aeson                   as Aeson
import qualified Data.Aeson.Encode.Pretty     as Aeson
import           Data.Bits                    (shiftL, (.|.))
import qualified Data.ByteArray               as BA
import           Data.ByteString              (ByteString)
import qualified Data.ByteString              as BS
import qualified Data.ByteString.Base16       as B16
import           Data.ByteString.Base58       (bitcoinAlphabet, encodeBase58)
import qualified Data.ByteString.Char8        as B8
import qualified Data.ByteString.Lazy         as BL
import qualified Data.ByteString.Lazy.Char8   as BL8
import           Data.Digest.CRC32            (crc32)
import           Data.Int                     (Int64)
import           Data.List                    (intersect, partition)
import           Data.List.NonEmpty           (NonEmpty (..))
import           Data.Map.Strict              (Map)
import qualified Data.Map.Strict              as Map
import           Data.Set                     (Set, (\\))
import qualified Data.Set                     as Set
import qualified Data.Text.Encoding           as T
import           Data.Time.Clock              (diffUTCTime, getCurrentTime)
import           Data.Word                    (Word16, Word32, Word64, Word8)
import           Debug.Trace                  (trace, traceShow)
import           GHC.Generics                 (Generic)
import           GHC.TypeLits                 (Symbol)
import           Network.HTTP.Client          (Manager, defaultRequest, httpLbs,
                                               path, port, responseBody,
                                               responseStatus)
import qualified Network.HTTP.Client          as HTTP

import           Cardano.Crypto.Wallet        (ChainCode (..),
                                               DerivationScheme (..), XPrv,
                                               XPub (..), deriveXPrv,
                                               deriveXPub, generate,
                                               generateNew, toXPub, unXPub)


main :: IO ()
main = runTests *> do
    network <- newNetworkLayer
    return ()

--    epochs <- timed "Get Epochs 0 -> tip" $ traverse (getEpoch network) [0..50]
--
--    let (emptyBlocks, nonEmptyBlocks) = partition (Set.null . transactions) (mconcat epochs)
--
--    putStrLn $ "EMPTY BLOCKS:     " <> show (length emptyBlocks)
--    putStrLn $ "NON EMPTY BLOCKS: " <> show (length nonEmptyBlocks)
--
--    let addrs = map (deriveAddress yoroiXPrv ExternalChain) [0..10]
--            <> map (deriveAddress yoroiXPrv InternalChain) [0..10]
--    let isOurs (Tx _ outs) =
--            not $ null $ intersect addrs (address <$> Map.elems outs)
--
--    timed "concat txs" $ do
--        let txs = filter isOurs (concatMap (Set.toList . transactions) $ mconcat epochs)
--        BL8.putStrLn $ Aeson.encodePretty txs


{-------------------------------------------------------------------------------
                            PRIMITIVE TYPES
--------------------------------------------------------------------------------}

class Dom a where
  type DomElem a :: *
  dom :: a -> Set (DomElem a)


data Block = Block
    { header       :: !BlockHeader
    , transactions :: !(Set Tx)
    } deriving (Show, Generic)

instance NFData Block

instance ToJSON Block where
    toJSON = Aeson.genericToJSON Aeson.defaultOptions


data BlockHeader = BlockHeader
    { epochIndex    :: !Word64
    , slotNumber    :: !Word16
    , previousBlock :: !BlockHeaderHash
    } deriving (Show, Generic)

instance NFData BlockHeader

instance ToJSON BlockHeader where
    toJSON = Aeson.genericToJSON Aeson.defaultOptions


newtype BlockHeaderHash = BlockHeaderHash
    { getBlockHeaderHash :: ByteString
    } deriving (Show, Generic)

instance NFData BlockHeaderHash

instance ToJSON BlockHeaderHash where
    toJSON = Aeson.String . T.decodeUtf8 . getBlockHeaderHash


data Tx = Tx
    { inputs  :: !(Set TxIn)
    , outputs :: !(Map Word32 TxOut)
    } deriving (Show, Ord, Eq, Generic)

instance NFData Tx

instance ToJSON Tx where
    toJSON = Aeson.genericToJSON Aeson.defaultOptions


newtype Address = Address
    { getAddress :: ByteString
    } deriving (Show, Ord, Eq, Generic)

instance NFData Address

instance ToJSON Address where
    toJSON = Aeson.String . T.decodeUtf8 . encodeBase58 bitcoinAlphabet . getAddress


newtype TxId = TxId
    { getTxId :: ByteString
    } deriving (Show, Ord, Eq, Generic)

instance NFData TxId

instance ToJSON TxId where
    toJSON = Aeson.String . T.decodeUtf8 . B16.encode . getTxId

data TxIn = TxIn
    { txId    :: !TxId
    , txIndex :: !Word32
    } deriving (Show, Ord, Eq, Generic)

instance NFData TxIn

instance ToJSON TxIn where
    toJSON = Aeson.genericToJSON Aeson.defaultOptions


data TxOut = TxOut
    { address :: !Address
    , coin    :: !Coin
    } deriving (Show, Ord, Eq, Generic)

instance NFData TxOut

instance ToJSON TxOut where
    toJSON = Aeson.genericToJSON Aeson.defaultOptions


newtype Coin = Coin
    { getCoin :: Word64
    } deriving (Show, Ord, Eq, Generic)

instance NFData Coin

instance ToJSON Coin where
    toJSON = toJSON . getCoin

instance Semigroup Coin where
  (Coin a) <> (Coin b) = Coin (a + b)

instance Monoid Coin where
  mempty  = Coin 0
  mconcat = foldr (<>) mempty

data TxWitness = TxWitness deriving (Show)


newtype UTxO = UTxO (Map TxIn TxOut)
  deriving (Eq, Ord)

instance Semigroup UTxO where
  (UTxO a) <> (UTxO b) = UTxO (a <> b)

instance Monoid UTxO where
  mempty  = UTxO mempty
  mconcat = foldr (<>) mempty

instance Dom UTxO where
  type DomElem UTxO = TxIn
  dom (UTxO utxo)   = Set.fromList $ Map.keys utxo


{-------------------------------------------------------------------------------
                           WALLET BUSINESS LOGIC
--------------------------------------------------------------------------------}

-- Assumed to be 'effectively' injective (2.1 UTxO-style Accounting)
txid :: Tx -> TxId
txid =
  error "How to compute a 'unique' identifier from a Transaction (e.g. hashing)?"

-- This only satistfies for single-account model
addressIsOurs :: Address -> Bool
addressIsOurs =
  error "How to tell whether an address is ours?"


-- * Tx Manipulation

txins :: Set Tx -> Set TxIn
txins =
    Set.unions . Set.map inputs

txutxo :: Set Tx -> UTxO
txutxo =
    Set.foldr' (<>) (UTxO mempty) . Set.map utxo
 where
    utxo :: Tx -> UTxO
    utxo tx@(Tx _ outs) =
        UTxO $ Map.mapKeys (TxIn (txid tx)) outs

txoutsOurs :: Set Tx -> Set TxOut
txoutsOurs =
    Set.unions . Set.map txoutOurs
 where
    txoutOurs :: Tx -> Set TxOut
    txoutOurs (Tx _ outs) =
        Set.filter (addressIsOurs . address) $ Set.fromList $ Map.elems outs


-- * UTxO Manipulation

-- ins⊲ u
restrictedBy :: UTxO -> Set TxIn -> UTxO
restrictedBy (UTxO utxo) =
    UTxO . Map.restrictKeys utxo

-- ins⋪ u
excluding :: UTxO -> Set TxIn ->  UTxO
excluding (UTxO utxo) =
    UTxO . Map.withoutKeys utxo

-- u ⊳ outs
restrictedTo :: UTxO -> Set TxOut ->  UTxO
restrictedTo (UTxO utxo) outs =
    UTxO $ Map.filter (`Set.member` outs) utxo

-- a ⊆ b
isSubsetOf :: UTxO -> UTxO -> Bool
isSubsetOf (UTxO a) (UTxO b) =
    a `Map.isSubmapOf` b

balance :: UTxO -> Coin
balance (UTxO utxo) =
    mconcat $ map coin $ Map.elems utxo

changeUTxO :: Set Tx -> UTxO
changeUTxO pending =
    let
        ours = txoutsOurs pending
        ins  = txins pending
    in
        (txutxo pending `restrictedTo` ours) `restrictedBy` ins

updateUTxO :: Block -> UTxO -> UTxO
updateUTxO b utxo =
    let
        txs   = transactions b
        utxo' = txutxo txs `restrictedTo` txoutsOurs txs
        ins   = txins txs
    in
        (utxo <> utxo') `excluding` ins

updatePending :: Block -> Set Tx -> Set Tx
updatePending b =
    let
        isStillPending ins = Set.null . Set.intersection ins . inputs
    in
        Set.filter (isStillPending (txins $ transactions b))


-- * Wallet

data Wallet = Wallet
    { walletUTxO    :: UTxO
    , walletPending :: Set Tx
    }

type Checkpoints = NonEmpty Wallet

instance Semigroup Wallet where
    (Wallet u1 p1) <> (Wallet u2 p2) =
        Wallet (u1 <> u2) (p1 <> p2)

instance Monoid Wallet where
  mempty  = Wallet mempty mempty
  mconcat = foldr (<>) mempty

availableBalance :: Wallet -> Coin
availableBalance =
    balance . availableUTxO

availableUTxO :: Wallet -> UTxO
availableUTxO (Wallet utxo pending) =
    utxo `excluding` txins pending

totalUTxO :: Wallet -> UTxO
totalUTxO wallet@(Wallet _ pending) =
    availableUTxO wallet <> changeUTxO pending

totalBalance :: Wallet -> Coin
totalBalance =
    balance . totalUTxO

applyBlock :: Block -> Checkpoints -> Checkpoints
applyBlock b (Wallet utxo pending :| checkpoints) =
    invariant applyBlockSafe "applyBlock requires: dom (utxo b) ∩ dom utxo = ∅" $
        Set.null $ dom (txutxo $ transactions b) `Set.intersection` dom utxo
  where
    applyBlockSafe =
        Wallet (updateUTxO b utxo) (updatePending b pending) :| checkpoints

newPending :: Tx -> Checkpoints -> Checkpoints
newPending tx (wallet@(Wallet utxo pending) :| checkpoints) =
    invariant newPendingSafe "newPending requires: ins ⊆ dom (available (utxo, pending))" $
        Set.null $ inputs tx \\ dom (availableUTxO wallet)
  where
    newPendingSafe =
        Wallet utxo (pending <> Set.singleton tx) :| checkpoints

rollback :: Checkpoints -> Checkpoints
rollback = \case
    Wallet _ pending :| Wallet utxo' pending' : checkpoints ->
        Wallet utxo' (pending <> pending') :| checkpoints
    checkpoints ->
        checkpoints


{-------------------------------------------------------------------------------
                             ADDRESS DERIVATION
--------------------------------------------------------------------------------}

-- We introduce some phantom types here to force disctinction between the
-- various key types we have.
newtype Key (scheme :: Scheme) (level :: Depth) = Key { getKey :: XPrv }

data Scheme
    = Seq
    | Rnd

data Depth
    = Root0
    | Acct3
    | Addr5

data ChangeChain
    = InternalChain
    | ExternalChain
    deriving (Show, Eq)

-- Not deriving 'Enum' because this could have a dramatic impact if we were
-- to assign the wrong index to the corresponding constructor.
instance Enum ChangeChain where
    toEnum = \case
        0 -> ExternalChain
        1 -> InternalChain
        _ -> error "ChangeChain.toEnum: bad argument"
    fromEnum = \case
        ExternalChain -> 0
        InternalChain -> 1

class HierarchicalDerivation (scheme :: Scheme) where
    deriveAccountPrivateKey
        :: ByteString -- Passphrase used to encrypt Master Private Key
        -> Key scheme 'Root0 -- Master Private Key
        -> Word32 -- Hardened Account Key Index
        -> Key scheme 'Acct3 -- Account Private Key

    deriveAddressPrivateKey
        :: ByteString -- Passphrase used to encrypt Account Private Key
        -> Key scheme 'Acct3 -- Account Private Key
        -> ChangeChain -- Change chain
        -> Word32 -- Non-hardened Address Key Index
        -> Key scheme 'Addr5 -- Address Private Key

class ToAddress (scheme :: Scheme) where
    type ToAddressArgs scheme :: *
    toAddress
        :: Key scheme 'Addr5
        -> ToAddressArgs scheme
        -> Address


-- * Random Derivation

instance HierarchicalDerivation 'Rnd where
    deriveAccountPrivateKey passPhrase (Key masterXPrv) accountIx =
        Key $ deriveXPrv DerivationScheme1 passPhrase masterXPrv accountIx

    deriveAddressPrivateKey passPhrase (Key accXPrv) _ addressIx =
        Key $ deriveXPrv DerivationScheme1 passPhrase accXPrv addressIx


data RandomAddressArgs = RandomAddressArgs
    { rndAccountIx :: Word32
    , rndAddressIx :: Word32
    , rndRootXPrv  :: Key 'Rnd 'Root0
    }

instance ToAddress 'Rnd where
    type ToAddressArgs 'Rnd = RandomAddressArgs
    toAddress (Key xprv) (RandomAddressArgs rndAccountIx rndAddressIx rndRootXPrv) = Address $
        CBOR.toStrictByteString $ mempty
            <> CBOR.encodeListLen 2
            <> CBOR.encodeTag 24 -- Hard-Coded Tag value in cardano-sl
            <> CBOR.encodeBytes payload
            <> CBOR.encodeWord32 (crc32 payload)
      where
        payload = CBOR.toStrictByteString $ mempty
            <> CBOR.encodeListLen 3
            <> CBOR.encodeBytes root
            <> encodeAttributes
            <> CBOR.encodeWord8 0 -- Address Type, 0 = Public Key

        root = BA.convert $ hash @_ @Blake2b_224 $ hash @_ @SHA3_256 $ CBOR.toStrictByteString $ mempty
            <> CBOR.encodeListLen 3
            <> CBOR.encodeWord8 0 -- Address Type, 0 = Public Key
            <> encodeSpendingData
            <> encodeAttributes

        passphrase (Key rootXPrv) = PBKDF2.generate
            (PBKDF2.prfHMAC SHA512)
            (PBKDF2.Parameters 500 32)
            (unXPub $ toXPub rootXPrv)
            ("address-hashing" :: ByteString)

        encodeXPub (XPub pub (ChainCode cc)) =
            CBOR.encodeBytes (pub <> cc)

        encodeSpendingData = CBOR.encodeListLen 2
            <> CBOR.encodeWord8 0
            <> encodeXPub (toXPub xprv)

        encodeAttributes = CBOR.encodeMapLen 1
            <> CBOR.encodeWord8 1
            <> encodeDerivationPath (passphrase rndRootXPrv)

        encodeDerivationPath passphrase =
            let
                path = CBOR.toStrictByteString $ mempty
                    <> CBOR.encodeListLenIndef
                    <> CBOR.encodeWord32 rndAccountIx
                    <> CBOR.encodeWord32 rndAddressIx
                    <> CBOR.encodeBreak
            in
                case encryptDerPath passphrase path of
                    CryptoPassed a ->
                        CBOR.encodeBytes $ CBOR.toStrictByteString $ CBOR.encodeBytes a
                    CryptoFailed e ->
                        error $ "toAddress.encodeDerivationPath : " <> show e

-- | Gotta love Serokell hard-coded nonce :) .. Kill me now.
cardanoNonce :: ByteString
cardanoNonce = "serokellfore"

-- | Simplified ChaChaPoly encryption used for encrypting the HD payload of the
-- address.
encryptDerPath
    :: ByteString -- Symmetric key / passphrase, 32-byte long
    -> ByteString -- Payload to be encrypted
    -> CryptoFailable ByteString -- Ciphertext with a 128-bit crypto-tag appended.
encryptDerPath passphrase payload = do
    nonce <- Poly.nonce12 cardanoNonce
    st1 <- Poly.finalizeAAD <$> Poly.initialize passphrase nonce
    let (out, st2) = Poly.encrypt payload st1
    return $ out <> BA.convert (Poly.finalize st2)

decryptDerPath
    :: ByteString -- Symmetric key / passphrase, 32-byte long
    -> ByteString -- Payload to be encrypted
    -> CryptoFailable ByteString
decryptDerPath passphrase bytes = do
    let (payload, tag) = BS.splitAt (BS.length bytes - 16) bytes
    nonce <- Poly.nonce12 cardanoNonce
    st1 <- Poly.finalizeAAD <$> Poly.initialize passphrase nonce
    let (out, st2) = Poly.decrypt payload st1
    when (BA.convert (Poly.finalize st2) /= tag) $ CryptoFailed CryptoError_MacKeyInvalid
    return out


-- * Sequential Derivation

purposeIndex :: Word32
purposeIndex = 0x8000002C

coinTypeIndex :: Word32
coinTypeIndex = 0x80000717

instance HierarchicalDerivation 'Seq where
    deriveAccountPrivateKey passPhrase (Key masterXPrv) accountIx =
        let -- lvl1 derivation in bip44 is hardened derivation of purpose' chain
            purposeXPrv = deriveXPrv DerivationScheme2 passPhrase masterXPrv purposeIndex
            -- lvl2 derivation in bip44 is hardened derivation of coin_type' chain
            coinTypeXPrv = deriveXPrv DerivationScheme2 passPhrase purposeXPrv coinTypeIndex
            -- lvl3 derivation in bip44 is hardened derivation of account' chain
            acctXPrv = deriveXPrv DerivationScheme2 passPhrase coinTypeXPrv accountIx
        in
            Key acctXPrv

    deriveAddressPrivateKey passPhrase (Key accXPrv) changeChain addressIx =
        let -- lvl4 derivation in bip44 is derivation of change chain
            changeXPrv = deriveXPrv DerivationScheme2 passPhrase accXPrv (fromIntegral $ fromEnum changeChain)
            -- lvl5 derivation in bip44 is derivation of address chain
            addrXPrv = deriveXPrv DerivationScheme2 passPhrase changeXPrv addressIx
        in
            Key addrXPrv

instance ToAddress 'Seq where
    type ToAddressArgs 'Seq = ()
    toAddress (Key xprv) () = Address $ CBOR.toStrictByteString $ mempty
        <> CBOR.encodeListLen 2
        <> CBOR.encodeTag 24 -- Hard-Coded Tag value in cardano-sl
        <> CBOR.encodeBytes payload
        <> CBOR.encodeWord32 (crc32 payload)
      where
        payload = CBOR.toStrictByteString $ mempty
            <> CBOR.encodeListLen 3
            <> CBOR.encodeBytes root
            <> encodeAttributes
            <> CBOR.encodeWord8 0 -- Address Type, 0 = Public Key

        root = BA.convert $ hash @_ @Blake2b_224 $ hash @_ @SHA3_256 $ CBOR.toStrictByteString $ mempty
            <> CBOR.encodeListLen 3
            <> CBOR.encodeWord8 0 -- Address Type, 0 = Public Key
            <> encodeSpendingData
            <> encodeAttributes

        encodeXPub (XPub pub (ChainCode cc)) =
            CBOR.encodeBytes (pub <> cc)

        encodeSpendingData = CBOR.encodeListLen 2
            <> CBOR.encodeWord8 0
            <> encodeXPub (toXPub xprv)

        encodeAttributes = CBOR.encodeMapLen 0


{-------------------------------------------------------------------------------
                             ADDRESS DISCOVERY
--------------------------------------------------------------------------------}


{-------------------------------------------------------------------------------
                              NETWORK LAYER
--------------------------------------------------------------------------------}

data NetworkLayer = NetworkLayer
    { getBlock      :: BlockHeaderHash -> IO Block
    , getEpoch      :: Int -> IO [Block]
    , getNetworkTip :: IO BlockHeader
    }


mkNetworkLayer :: Manager -> NetworkLayer
mkNetworkLayer manager = NetworkLayer
    { getBlock = _getBlock manager
    , getEpoch = _getEpoch manager
    , getNetworkTip = _getNetworkTip manager
    }


newNetworkLayer :: IO NetworkLayer
newNetworkLayer = do
    manager <- HTTP.newManager HTTP.defaultManagerSettings
    return $ mkNetworkLayer manager


_getBlock :: Manager -> BlockHeaderHash -> IO Block
_getBlock manager (BlockHeaderHash hash) = do
    let req = defaultRequest
            { port = 1337
            , path = "/mainnet/block/" <> hash
            }
    res <- httpLbs req manager
    let block = unsafeDeserialiseFromBytes decodeBlock $ responseBody res
    return block


_getEpoch :: Manager -> Int -> IO [Block]
_getEpoch manager n = do
    let req = defaultRequest
            { port = 1337
            , path = "/mainnet/epoch/" <> B8.pack (show n)
            }
    res <- httpLbs req manager
    let epoch = deserialiseEpoch decodeBlock (responseBody res)
    return epoch


_getNetworkTip :: Manager -> IO BlockHeader
_getNetworkTip manager = do
    let req = defaultRequest
            { port = 1337
            , path = "/mainnet/tip"
            }
    res <- httpLbs req manager
    let tip = unsafeDeserialiseFromBytes decodeBlockHeader $ responseBody res
    return tip


{-------------------------------------------------------------------------------
                                DESERIALISER

    # Epoch

    Epoch are serialized in pack files that are concatenation of encoded blocks.
    Each block is encoded as:
      * A 4 bytes 'size' in big endian
      * A CBOR blob of 'size' bytes
      * 0 to 3 bytes of 'alignment' bytes, such that: 'size' + 'alignment' ≡  4

    # Block

    Block are encoded using CBOR, with a format described in 'CBOR DECODERS'

--------------------------------------------------------------------------------}

unsafeDeserialiseFromBytes :: (forall s. CBOR.Decoder s a) -> BL.ByteString -> a
unsafeDeserialiseFromBytes decoder bytes =
    either (\e -> error $ "unsafeDeserialiseFromBytes: " <> show e) snd $
        CBOR.deserialiseFromBytes decoder bytes

deserialiseEpoch :: CBOR.Decoder s Block -> BL.ByteString -> [Block]
deserialiseEpoch decoder = deserialiseEpoch' [] . checkHeader
  where
    checkHeader :: BL.ByteString -> BL.ByteString
    checkHeader bytes =
        let (magic, filetype, version) =
                ( BL.take 8 bytes
                , BL.take 4 $ BL.drop 8 bytes
                , BL.take 4 $ BL.drop 12 bytes
                )
        in
            if magic == "\254CARDANO" && filetype == "PACK" && version == BL.pack [0,0,0,1] then
                BL.drop 16 bytes
            else
                error $ "INVALID PACK FILE MAGIC: "
                    <> BL8.unpack magic <> ", "
                    <> BL8.unpack filetype <> ", "
                    <> BL8.unpack version

    deserialiseEpoch' :: [Block] -> BL.ByteString -> [Block]
    deserialiseEpoch' !epoch bytes
        | BL.null bytes =
            -- NOTE
            -- We remove the genesis block has it contains very little information
            -- for the wallet backend. We do also reverse the list to get block
            -- in order since we've been prepending blocks to construct the
            -- epoch and avoid making the algorithm complexity explodes. Cf below.
            drop 1 (reverse epoch)
        | otherwise =
            let
                (size, r0) =
                    first (fromIntegral . word32) $ BL.splitAt 4 bytes

                (blkBytes, r1) =
                    BL.splitAt size r0

                block =
                    unsafeDeserialiseFromBytes decodeBlock blkBytes
            in
                -- NOTE
                -- Careful here when appending blocks to the accumulator 'epoch'
                -- doing a naive `epoch ++ [block]` has a dramatic impact on the
                -- complexity. So we better append elements and reverse the list
                -- at the end!
                deserialiseEpoch' (block : epoch) (BL.drop (pad size) r1)

    pad :: Int64 -> Int64
    pad n =
        -(n `mod` (-4))

    word32 :: BL.ByteString -> Word32
    word32 bytes = case fromIntegral <$> BL.unpack bytes of
        [a,b,c,d] ->
            shiftL a 24 .|. shiftL b 16 .|. shiftL c 8 .|. d
        _ ->
            error "deserialiseEpoch.word32: expected exactly 4 bytes!"


{-------------------------------------------------------------------------------
                              CBOR DECODERS

   (Partial) CBOR Decoders for Blocks and Block Headers. Note that, we do
   ignore most of the block's and header's content and only retrieve the
   pieces of information relevant to us, wallet (we do assume a trusted
   node and therefore, we needn't to care about verifying signatures and
   blocks themselves).

   Still, if needed, holes can be filled to retrieve additional details.
   There's a _rather_ straightforward mapping with `cardano-sl/chain` and
   `cardano-sl/core` representations; comments and functions' name should
   make it clear what the decoders are about.

   In case of issue with a decode, the @inspectNextToken@ function may come
   in handy to debug and see what CBOR is actually expecting behind the scene.
--------------------------------------------------------------------------------}

decodeAddress :: CBOR.Decoder s Address
decodeAddress = do
    _ <- CBOR.decodeListLenCanonicalOf 2 -- CRC Protection Wrapper
    tag <- CBOR.decodeTag -- Myterious hard-coded tag cardano-sl seems to so much like
    bytes <- CBOR.decodeBytes -- Addr Root + Attributes + Type
    crc <- CBOR.decodeWord32 -- CRC
    -- NOTE 1:
    -- Treating addresses as a blob here, so we just reencod them as such
    -- Ultimately for us, addresses are nothing more than a bunch of bytes that
    -- we display in a Base58 format when we have too.
    --
    -- NOTE 2:
    -- We may want to check the CRC at this level as-well... maybe not.
    return $ Address $ CBOR.toStrictByteString $ mempty
        <> CBOR.encodeListLen 2
        <> CBOR.encodeTag tag
        <> CBOR.encodeBytes bytes
        <> CBOR.encodeWord32 crc

decodeAttributes :: CBOR.Decoder s ()
decodeAttributes = do
    _ <- CBOR.decodeMapLenCanonical -- Empty map of attributes
    return ()

decodeBlock :: CBOR.Decoder s Block
decodeBlock = do
    CBOR.decodeListLenCanonicalOf 2
    t <- CBOR.decodeWordCanonical
    case t of
        0 -> do -- Genesis Block
            _ <- CBOR.decodeListLenCanonicalOf 3
            header <- decodeGenesisBlockHeader
            -- NOTE
            -- We don't decode the body of genesis block because we don't
            -- need it (see @decodeGenesisBlockBody@). Genesis blocks occurs at
            -- every epoch boundaries and contains various information about
            -- protocol updates, slot leaders elections and delegation.
            -- Yet, they don't contain any transaction and we can get away with
            -- a 'mempty' here.
            return $ Block header mempty

        1 -> do -- Main Block
            _ <- CBOR.decodeListLenCanonicalOf 3
            header <- decodeMainBlockHeader
            transactions <- decodeMainBlockBody
            -- _ <- decodeMainExtraData
            return $ Block header transactions

        _ -> do
            fail $ "decodeBlock: unknown block constructor: " <> show t

decodeBlockHeader :: CBOR.Decoder s BlockHeader
decodeBlockHeader = do
    CBOR.decodeListLenCanonicalOf 2
    t <- CBOR.decodeWordCanonical
    case t of
      0 -> decodeGenesisBlockHeader
      1 -> decodeMainBlockHeader
      _ -> fail $ "decodeBlockHeader: unknown block header constructor: " <> show t

decodeBlockVersion :: CBOR.Decoder s ()
decodeBlockVersion = do
    _ <- CBOR.decodeListLenCanonicalOf 3
    _ <- CBOR.decodeWord16 -- Major
    _ <- CBOR.decodeWord16 -- Minor
    _ <- CBOR.decodeWord8  -- Patch
    return ()

decodeDataProof :: CBOR.Decoder s ()
decodeDataProof = do
    _ <- CBOR.decodeBytes -- Proof Hash
    return ()

decodeCertificatesProof :: CBOR.Decoder s ()
decodeCertificatesProof = do
    _ <- CBOR.decodeBytes -- Vss Certificates Hash
    return ()

decodeCommitmentsProof :: CBOR.Decoder s ()
decodeCommitmentsProof = do
    _ <- CBOR.decodeBytes -- Commitments Hash
    _ <- CBOR.decodeBytes -- Vss Certificates Hash
    return ()

decodeDifficulty :: CBOR.Decoder s ()
decodeDifficulty = do
    _ <- CBOR.decodeListLenCanonicalOf 1
    _ <- CBOR.decodeWord64
    return ()

decodeGenesisBlockHeader :: CBOR.Decoder s BlockHeader
decodeGenesisBlockHeader = do
    _ <- CBOR.decodeListLenCanonicalOf 5
    _ <- decodeProtocolMagic
    previous <- decodePreviousBlockHeader
    _ <- decodeGenesisProof
    epochIndex <- decodeGenesisConsensusData
    _ <- decodeGenesisExtraData
    -- NOTE
    -- Careful here, we do return a slot number of 0, which means that if we
    -- naively parse all blocks from an epoch, two of them will have a slot
    -- number of `0`. In practices, when parsing a full epoch, we can discard
    -- the genesis block entirely and we won't bother about modelling this
    -- extra complexity at the type-level. That's a bit dodgy though.
    return $ BlockHeader epochIndex 0 previous

decodeGenesisConsensusData :: CBOR.Decoder s Word64
decodeGenesisConsensusData = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    epochIndex <- CBOR.decodeWord64
    _ <- decodeDifficulty
    return epochIndex

decodeGenesisExtraData :: CBOR.Decoder s ()
decodeGenesisExtraData = do
    _ <- CBOR.decodeListLenCanonicalOf 1
    _ <- decodeAttributes
    return ()

decodeGenesisProof :: CBOR.Decoder s ()
decodeGenesisProof = do
    _ <- CBOR.decodeBytes -- Slot Leaders Hash
    return ()

decodeHeavyIndex :: CBOR.Decoder s ()
decodeHeavyIndex = do
    _ <- CBOR.decodeWord64 -- Epoch Index
    return ()

decodeLeaderKey :: CBOR.Decoder s ()
decodeLeaderKey = do
    _ <- CBOR.decodeBytes
    return ()

decodeLightIndex :: CBOR.Decoder s ()
decodeLightIndex = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    _ <- CBOR.decodeWord64 -- Epoch Index #1
    _ <- CBOR.decodeWord64 -- Epoch Index #2
    return ()

decodeMainBlockBody :: CBOR.Decoder s (Set Tx)
decodeMainBlockBody = do
    _ <- CBOR.decodeListLenCanonicalOf 4
    decodeTxPayload
    -- NOTE:
    -- Would remain after that:
    --  - SscPayload
    --  - DlsPayload
    --  - UpdatePayload

decodeMainBlockHeader :: CBOR.Decoder s BlockHeader
decodeMainBlockHeader = do
    _ <- CBOR.decodeListLenCanonicalOf 5
    _ <- decodeProtocolMagic
    previous <- decodePreviousBlockHeader
    _ <- decodeMainProof
    (epochIndex, slotNumber) <- decodeMainConsensusData
    _ <- decodeMainExtraData
    return $ BlockHeader epochIndex slotNumber previous

decodeMainConsensusData :: CBOR.Decoder s (Word64, Word16)
decodeMainConsensusData = do
    _ <- CBOR.decodeListLenCanonicalOf 4
    slot <- decodeSlotId
    _ <- decodeLeaderKey
    _ <- decodeDifficulty
    _ <- decodeSignature
    return slot

decodeMainExtraData :: CBOR.Decoder s ()
decodeMainExtraData = do
    _ <- CBOR.decodeListLenCanonicalOf 4
    _ <- decodeBlockVersion
    _ <- decodeSoftwareVersion
    _ <- decodeAttributes
    _ <- decodeDataProof
    return ()

decodeMainProof :: CBOR.Decoder s ()
decodeMainProof = do
    CBOR.decodeListLenCanonicalOf 4
    decodeTxProof
    decodeMpcProof
    decodeProxySKsProof
    decodeUpdateProof

decodeMpcProof :: CBOR.Decoder s ()
decodeMpcProof = do
    _ <- CBOR.decodeListLenCanonical
    t <- CBOR.decodeWord8
    case t of
      0 -> decodeCommitmentsProof
      1 -> decodeOpeningsProof
      2 -> decodeSharesProof
      3 -> decodeCertificatesProof
      _ -> error $ "TODO: decodeMpcProof: unknown proof constructor: " <> show t

decodeOpeningsProof :: CBOR.Decoder s ()
decodeOpeningsProof = do
    _ <- CBOR.decodeBytes -- Openings Hash
    _ <- CBOR.decodeBytes -- Vss Certificates Hash
    return ()

decodePreviousBlockHeader :: CBOR.Decoder s BlockHeaderHash
decodePreviousBlockHeader =
    BlockHeaderHash . B16.encode <$> CBOR.decodeBytes

decodeProtocolMagic :: CBOR.Decoder s ()
decodeProtocolMagic = do
    _ <- CBOR.decodeInt32
    return ()

decodeProxySignature
    :: (forall s. CBOR.Decoder s ())
    -> CBOR.Decoder s ()
decodeProxySignature decodeIndex = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    _ <- decodeProxySecretKey
    _ <- CBOR.decodeBytes -- Proxy Signature
    return ()
  where
    decodeProxySecretKey :: CBOR.Decoder s ()
    decodeProxySecretKey = do
        _ <- CBOR.decodeListLenCanonicalOf 4
        _ <- decodeIndex
        _ <- CBOR.decodeBytes -- Issuer Public Key
        _ <- CBOR.decodeBytes -- Delegate Public Key
        _ <- CBOR.decodeBytes -- Proxy Certificate Key
        return ()

decodeProxySKsProof :: CBOR.Decoder s ()
decodeProxySKsProof = do
    _ <- CBOR.decodeBytes -- Dlg Payload Hash
    return ()

decodeSignature :: CBOR.Decoder s ()
decodeSignature = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    t <- CBOR.decodeWord8
    case t of
        0 -> void CBOR.decodeBytes
        1 -> decodeProxySignature decodeLightIndex
        2 -> decodeProxySignature decodeHeavyIndex
        _ -> fail $ "decodeSignature: unknown signature constructor: " <> show t

decodeSharesProof :: CBOR.Decoder s ()
decodeSharesProof = do
    _ <- CBOR.decodeBytes -- Shares Hash
    _ <- CBOR.decodeBytes -- Vss Certificates Hash
    return ()

decodeSlotId :: CBOR.Decoder s (Word64, Word16)
decodeSlotId = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    epochIndex <- CBOR.decodeWord64
    slotNumber <- CBOR.decodeWord16
    return (epochIndex, slotNumber)

decodeSoftwareVersion :: CBOR.Decoder s ()
decodeSoftwareVersion = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    _ <- CBOR.decodeString -- Application Name
    _ <- CBOR.decodeWord32 -- Software Version
    return ()

decodeTx :: CBOR.Decoder s (Tx, TxWitness)
decodeTx = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    _ <- CBOR.decodeListLenCanonicalOf 3
    inputs <- decodeListIndef decodeTxIn
    outputs <- decodeListIndef decodeTxOut
    _ <- decodeAttributes
    _ <- decodeList decodeTxWitness
    return (Tx (Set.fromList inputs) (Map.fromList (zip [0..] outputs)), TxWitness)

decodeTxPayload :: CBOR.Decoder s (Set Tx)
decodeTxPayload = do
    (txs, _) <- unzip <$> decodeListIndef decodeTx
    return $ Set.fromList txs

decodeTxIn :: CBOR.Decoder s TxIn
decodeTxIn = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    t <- CBOR.decodeWord8
    case t of
        0 -> do
            _ <- CBOR.decodeTag
            bytes <- CBOR.decodeBytes
            case CBOR.deserialiseFromBytes decodeTxIn' (BL.fromStrict bytes) of
                Right (_, input) -> return input
                Left err         -> fail $ show err
        _ -> fail $ "decodeTxIn: unknown tx input constructor: " <> show t
  where
    decodeTxIn' :: CBOR.Decoder s TxIn
    decodeTxIn' = do
        _ <- CBOR.decodeListLenCanonicalOf 2
        txId <- CBOR.decodeBytes
        index <- CBOR.decodeWord32
        return $ TxIn (TxId txId) index

decodeTxOut :: CBOR.Decoder s TxOut
decodeTxOut = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    addr <- decodeAddress
    coin <- CBOR.decodeWord64
    return $ TxOut addr (Coin coin)

decodeTxProof :: CBOR.Decoder s ()
decodeTxProof = do
    CBOR.decodeListLenCanonicalOf 3
    _ <- CBOR.decodeWord32 -- Number
    _ <- CBOR.decodeBytes  -- Merkle Root Hash
    _ <- CBOR.decodeBytes  -- Witnesses Hash
    return ()

decodeTxWitness :: CBOR.Decoder s ()
decodeTxWitness = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    t <- CBOR.decodeWord8
    case t of
        0 -> CBOR.decodeTag *> CBOR.decodeBytes -- PKWitness
        1 -> CBOR.decodeTag *> CBOR.decodeBytes -- Script Witness
        2 -> CBOR.decodeTag *> CBOR.decodeBytes -- Redeem Witness
        _ -> fail $ "decodeTxWitness: unknown tx witness constructor: " <> show t
    return ()

decodeUpdateProof :: CBOR.Decoder s ()
decodeUpdateProof = do
    _ <- CBOR.decodeBytes -- Update Hash
    return ()


{-------------------------------------------------------------------------------
                                CBOR EXTRA

  Some Extra Helper on top of the CBOR library to help writing decoders.

--------------------------------------------------------------------------------}

-- | Inspect the next token that has to be decoded and print it to the console
-- as a trace. Useful for debugging Decoders.
-- Example:
--
--     myDecoder :: CBOR.Decoder s MyType
--     myDecoder = do
--         a <- CBOR.decodeWord64
--         inspectNextToken
--         [...]
--
inspectNextToken :: CBOR.Decoder s ()
inspectNextToken =
  CBOR.peekTokenType >>= flip traceShow (return ())

-- | Decode an list of known length. Very similar to @decodeListIndef@.
--
-- Example:
--
--     myDecoder :: CBOR.Decoder s [MyType]
--     myDecoder = decodeList decodeOne
--       where
--         decodeOne :: CBOR.Decoder s MyType
--
decodeList :: forall s a . CBOR.Decoder s a -> CBOR.Decoder s [a]
decodeList decodeOne = do
    l <- CBOR.decodeListLenCanonical
    CBOR.decodeSequenceLenN (flip (:)) [] reverse l decodeOne

-- | Decode an arbitrary long list. CBOR introduce a "break" character to
-- mark the end of the list, so we simply decode each item until we encounter
-- a break character.
--
-- Example:
--
--     myDecoder :: CBOR.Decoder s [MyType]
--     myDecoder = decodeListIndef decodeOne
--       where
--         decodeOne :: CBOR.Decoder s MyType
--
decodeListIndef :: forall s a. CBOR.Decoder s a -> CBOR.Decoder s [a]
decodeListIndef decodeOne = do
    _ <- CBOR.decodeListLenIndef
    CBOR.decodeSequenceLenIndef (flip (:)) [] reverse decodeOne


{-------------------------------------------------------------------------------
                                   UTILS

  Project various utils unrelated to any particular business logic.
--------------------------------------------------------------------------------}

timed :: NFData a => String -> IO a -> IO a
timed label io = do
    start <- getCurrentTime
    a <- io
    end <- a `deepseq` getCurrentTime
    putStrLn (label <> ": " <> show (diffUTCTime end start))
    return a

invariant :: a -> String -> Bool -> a
invariant next msg predicate =
  if predicate then next else error msg


{-------------------------------------------------------------------------------
                                   TESTING

  A bit of testing to compare this prototype implementation with the existing
  code on cardano-sl. It doesn't do much but at least, make sure that we
  generate and encode addresses correctly, comparing to what's on cardano-sl
  and cardano-wallet already.
--------------------------------------------------------------------------------}

runTests :: IO ()
runTests = do
    chachapolyRountrip
    addressGoldenTest

chachapolyRountrip :: IO ()
chachapolyRountrip = do
    let pw = BS.replicate 32 1 -- NOTE Passowrd must be a 32-length key
    invariant (return ()) "ChaChaPoly RoundTrip" $
        (encryptDerPath pw "patate" >>= decryptDerPath pw) == return "patate"

addressGoldenTest :: IO ()
addressGoldenTest = do
    invariant (return ()) "Address Golden Test - Yoroi 0'/0/0" $
        genYoroiAddr 0x80000000 0 ExternalChain == toJSON ("Ae2tdPwUPEZLLeQYaBmNXiwrv9Mf13eauCxgHxZYF1EhDKMTKR5t1dFrSCU" :: String)

    invariant (return ()) "Address Golden Test - Yoroi 0'/1/0" $
        genYoroiAddr 0x80000000 0 InternalChain == toJSON ("Ae2tdPwUPEZ9qDt13UhqJmNUALW56V9KhErnTAMsUwV4qm33CzfEmLP3tfP" :: String)

    invariant (return ()) "Address Golden Test - Yoroi 0'/0/14" $
        genYoroiAddr 0x80000000 14 ExternalChain == toJSON ("Ae2tdPwUPEZ6JkktL91gdeAEZrwxVyDfxE5GTJ9LLCnogcpe3GPd48m4Fir" :: String)

    invariant (return ()) "Address Golden Test - Yoroi 0'/1/14" $
        genYoroiAddr 0x80000000 14 InternalChain == toJSON ("Ae2tdPwUPEZEAgMFTZ3XvXupMJnbrKNxCtmBG4Ry4qBHYgCxe7T98fxr7uw" :: String)

    invariant (return ()) "Address Golden Test - Yoroi 14'/0/0" $
        genYoroiAddr 0x8000000E 0 ExternalChain == toJSON ("Ae2tdPwUPEZKCUMsknNU6FmV59dXGgHamS5cEfH6AR6u7bq5Y5RaneTBqBH" :: String)

    invariant (return ()) "Address Golden Test - Yoroi 14'/1/0" $
        genYoroiAddr 0x8000000E 0 InternalChain == toJSON ("Ae2tdPwUPEZ726BqcPdWdzSN42tPSu9Ryx4qEU9FBTLfBW8g5DU76FTn9Eo" :: String)

    invariant (return ()) "Address Golden Test - Yoroi 14'/0/42" $
        genYoroiAddr 0x8000000E 42 ExternalChain == toJSON ("Ae2tdPwUPEZGHqe3aWWBEGav6V6BuBZmB9XfQADZz6eagBaPZJCAtVrjXe2" :: String)

    invariant (return ()) "Address Golden Test - Yoroi 14'/1/42" $
        genYoroiAddr 0x8000000E 42 InternalChain == toJSON ("Ae2tdPwUPEZD6w2iqeQCyQt5dEhCnxwB5kooG8k2HhDoVc3myuHKWiD3fWi" :: String)

    invariant (return ()) "Address Golden Test - Daedalus 0'/0" $
        genDaedalusAddr 0x80000000 0 == toJSON ("2w1sdSJu3GViq5Rx3xYMS8twmKen9tQNya7DqHfQPzg5f6Lc6EXpDKoWA3wjiUk6dvN8bnUHZfhcSTXxkyHqBnzv7M15w52xJbq" :: String)

    invariant (return ()) "Address Golden Test - Daedalus 0'/14" $
        genDaedalusAddr 0x80000000 14 == toJSON ("2w1sdSJu3GVhSLVv1Yh7wmBT67tZ2KaXKEMFVUSy6rZnYbCJRjywkDSiU9ZZggvYSBK2hZ4C4MsaPwTJiKq99LvzYDmKgRgTBjF" :: String)

    invariant (return ()) "Address Golden Test - Daedalus 14'/0" $
        genDaedalusAddr 0x8000000E 0 == toJSON ("2w1sdSJu3GVieSGggHVpLxhgeh8Kno7oaBPyTFiKYJejSAMQ3vv1j2Lsx2jSTnuRgVgXbwtbTUUUmqJtitTAoUXJxKgZKJaYxFr" :: String)

    invariant (return ()) "Address Golden Test - Daedalus 14'/42" $
        genDaedalusAddr 0x8000000E 42 == toJSON ("9XQrTpiaBYn6K5uDNHphfxRXnGk3DMn7qDgxp2LditeMjueMhnYRmWmEbsUVsCodE3SJ6LQWzyVb51MYVp1pu2mAHJChz7UPJg4t" :: String)
  where
    genYoroiAddr accIx addrIx changeChain =
        let
            rootXPrv = Key yoroiXPrv :: Key 'Seq 'Root0
            acctXPrv = deriveAccountPrivateKey mempty rootXPrv accIx
            addrXPrv = deriveAddressPrivateKey mempty acctXPrv changeChain addrIx
        in
            toJSON $ toAddress addrXPrv ()

    genDaedalusAddr accIx addrIx =
        let
            rootXPrv = Key daedalusXPrv :: Key 'Rnd 'Root0
            acctXPrv = deriveAccountPrivateKey mempty rootXPrv accIx
            addrXPrv = deriveAddressPrivateKey mempty acctXPrv undefined addrIx
        in
            toJSON $ toAddress addrXPrv $ RandomAddressArgs
                { rndAccountIx = accIx
                , rndAddressIx = addrIx
                , rndRootXPrv  = rootXPrv
                }

    -- | A root private key using the sequential scheme on MAINNET.
    -- Kindly by Patrick from QA.
    yoroiXPrv :: XPrv
    yoroiXPrv = generateNew @ByteString @ByteString @ByteString
        "v\190\235Y\179#\181s]M\214\142g\178\245\DC4\226\220\f\167"
        mempty
        mempty

    -- | A root private key using the random scheme on MAINNET.
    -- Kindly provided by Alan from QA.
    daedalusXPrv = generate @ByteString @ByteString
        "X >\178\ETB\DLE\GSg\226\192\198z\131\189\186\220(A+\247\204h\253\235\&5\SUB\CAN\176g\223\212c|f"
        mempty
