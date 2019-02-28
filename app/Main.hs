{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedLabels           #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TypeApplications           #-}
{-# LANGUAGE TypeFamilies               #-}

{-| This module contains some prototypal code for a minimal viable wallet
   backend. It currently works with the existing Byron chain, and support the
   following features:

   - Basic Network Interface
   - Core Wallet Logic (UTxO tracking, Rollbacks, Balance...)
   - (legacy) Random Address Derivation
   - Sequential Address Derivation
   - Random Address Discovery
   - (almost) Sequential Address Discovery

  Note that a lot of things here aren't in an ideal form. Some types could be
  refined (for instance, password are usually just raw 'ByteString', and
  derivation indexes, hardened or not, are plain 'Word32'. Also, many functions
  are just assumed to succeed and not throw.

  Ideally, this serves multiple purposes:

  - Put the light on some major problems we could encounter once actually implementing this for real
  - Give a first idea of architecture and design that can fit everything
  - Allow reasonning to identify area of testing
  - Remove the dependency with cardano-sl by providing "the way" to implement the various compoenents
  - Identify some critical parts we may benchmark and control

  /!\ NOTE /!\
  This file contains actual mnemonic words of test wallet on mainnet. Don't
  share this and be careful when playing with those.
-}

module Main where

import qualified Codec.CBOR.Decoding              as CBOR
import qualified Codec.CBOR.Encoding              as CBOR
import qualified Codec.CBOR.Read                  as CBOR
import qualified Codec.CBOR.Write                 as CBOR
import           Control.Arrow                    (first)
import           Control.DeepSeq                  (NFData, deepseq)
import           Control.Monad                    (forM_, void, when)
import           Control.Monad.Trans.State.Strict (State, runState, state)
import qualified Crypto.Cipher.ChaChaPoly1305     as Poly
import           Crypto.Error                     (CryptoError (..),
                                                   CryptoFailable (..))
import           Crypto.Hash                      (hash)
import           Crypto.Hash.Algorithms           (Blake2b_224, Blake2b_256,
                                                   SHA3_256, SHA512 (..))
import qualified Crypto.KDF.PBKDF2                as PBKDF2
import           Data.Aeson                       (ToJSON (..))
import qualified Data.Aeson                       as Aeson
import qualified Data.Aeson.Encode.Pretty         as Aeson
import           Data.Bits                        (shiftL, (.|.))
import qualified Data.ByteArray                   as BA
import           Data.ByteString                  (ByteString)
import qualified Data.ByteString                  as BS
import qualified Data.ByteString.Base16           as B16
import           Data.ByteString.Base58           (bitcoinAlphabet,
                                                   encodeBase58)
import qualified Data.ByteString.Char8            as B8
import qualified Data.ByteString.Lazy             as BL
import qualified Data.ByteString.Lazy.Char8       as BL8
import           Data.Digest.CRC32                (crc32)
import           Data.Generics.Labels             ()
import           Data.Int                         (Int64)
import           Data.List                        (intersect, partition)
import           Data.List.NonEmpty               (NonEmpty (..))
import           Data.Map.Strict                  (Map)
import qualified Data.Map.Strict                  as Map
import           Data.Maybe                       (catMaybes, fromJust, isJust)
import           Data.Proxy                       (Proxy (..))
import           Data.Set                         (Set, (\\))
import qualified Data.Set                         as Set
import qualified Data.Text.Encoding               as T
import           Data.Time.Clock                  (diffUTCTime, getCurrentTime)
import           Data.Word                        (Word16, Word32, Word64,
                                                   Word8)
import           Debug.Trace                      (trace, traceShow)
import           GHC.Generics                     (Generic)
import           GHC.TypeLits                     (Symbol)
import           Lens.Micro                       (at, (%~), (&), (.~), (^.))
import           Network.HTTP.Client              (Manager, defaultRequest,
                                                   httpLbs, path, port,
                                                   responseBody, responseStatus)
import qualified Network.HTTP.Client              as HTTP

import           Cardano.Crypto.Wallet            (ChainCode (..),
                                                   DerivationScheme (..), XPrv,
                                                   XPub (..), deriveXPrv,
                                                   deriveXPub, generate,
                                                   generateNew, toXPub, unXPub)


main :: IO ()
main = do
    runTests
    network <- newNetworkLayer
    epochs <- syncWithMainnet network
--    restoreDaedalusWallet epochs >>= prettyPrint
    restoreYoroiWallet epochs >>= prettyPrint


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
    { inputId :: !TxId
    , inputIx :: !Word32
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


-- | Assumed to be effectively injective
txId :: Tx -> TxId
txId =
    TxId . BA.convert . hash @_ @Blake2b_256 . CBOR.toStrictByteString . encodeTx


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
        UTxO $ Map.mapKeys (TxIn (txId tx)) outs

txoutsOurs
    :: forall s. (Address -> s -> (Bool, s))
    -> Set Tx
    -> s
    -> (Set TxOut, s)
txoutsOurs isOurs txs =
    runState $ Set.fromList . mconcat <$> traverse txoutOurs (Set.toList txs)
 where
    txoutOurs :: Tx -> State s [TxOut]
    txoutOurs (Tx _ outs) = do
        outs' <- flip Map.traverseMaybeWithKey outs $ \_ out -> do
            predicate <- state $ isOurs (address out)
            return $ if predicate then Just out else Nothing
        return $ Map.elems outs


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

changeUTxO
    :: forall s. (Address -> s -> (Bool, s))
    -> Set Tx
    -> s
    -> (UTxO, s)
changeUTxO isOurs pending = runState $ do
    ours <- state $ txoutsOurs isOurs pending
    let ins  = txins pending
    return $ (txutxo pending `restrictedTo` ours) `restrictedBy` ins

updateUTxO
    :: forall s. (Address -> s -> (Bool, s))
    -> Block
    -> UTxO
    -> s
    -> (UTxO, s)
updateUTxO isOurs b utxo = runState $ do
    let txs = transactions b
    ours <- state $ txoutsOurs isOurs txs
    let utxo' = txutxo txs `restrictedTo` ours
    let ins = txins txs
    return $ (utxo <> utxo') `excluding` ins

updatePending :: Block -> Set Tx -> Set Tx
updatePending b =
    let
        isStillPending ins = Set.null . Set.intersection ins . inputs
    in
        Set.filter (isStillPending (txins $ transactions b))


-- * Wallet

data Wallet scheme where
    Wallet
        :: (IsOurs scheme, Semigroup (SchemeState scheme))
        => UTxO
        -> Set Tx
        -> SchemeState scheme
        -> Wallet scheme

type Checkpoints scheme = NonEmpty (Wallet scheme)

instance Semigroup (Wallet scheme) where
    (Wallet u1 p1 s1) <> (Wallet u2 p2 s2) =
        Wallet (u1 <> u2) (p1 <> p2) (s1 <> s2)

availableBalance :: Wallet scheme -> Coin
availableBalance =
    balance . availableUTxO

availableUTxO :: Wallet scheme -> UTxO
availableUTxO (Wallet utxo pending _) =
    utxo `excluding` txins pending

totalUTxO
    :: forall scheme. ()
    => Wallet scheme
    -> UTxO
totalUTxO wallet@(Wallet _ pending s) =
    let
        isOurs = addressIsOurs (Proxy :: Proxy scheme)
        -- NOTE
        -- We _safely_ discard the state here because we aren't intending to
        -- discover any new addresses through this operation. In practice, we can
        -- only discover new addresses when applying blocks.
        discardState = fst
    in
        availableUTxO wallet <> discardState (changeUTxO isOurs pending s)

totalBalance
    :: Wallet scheme
    -> Coin
totalBalance =
    balance . totalUTxO

applyBlock
    :: forall scheme. ()
    => Block
    -> Checkpoints scheme
    -> Checkpoints scheme
applyBlock b (Wallet utxo pending s :| checkpoints) =
    invariant applyBlockSafe "applyBlock requires: dom (utxo b) ∩ dom utxo = ∅" $
        Set.null $ dom (txutxo $ transactions b) `Set.intersection` dom utxo
  where
    applyBlockSafe =
        let
            (utxo', s') = updateUTxO (addressIsOurs (Proxy :: Proxy scheme)) b utxo s
            pending' = updatePending b pending
        in
            Wallet utxo' pending' s' :| checkpoints

newPending :: Tx -> Checkpoints scheme -> Checkpoints scheme
newPending tx (wallet@(Wallet utxo pending s) :| checkpoints) =
    invariant newPendingSafe "newPending requires: ins ⊆ dom (available (utxo, pending))" $
        Set.null $ inputs tx \\ dom (availableUTxO wallet)
  where
    newPendingSafe =
        Wallet utxo (pending <> Set.singleton tx) s :| checkpoints

rollback :: Checkpoints scheme -> Checkpoints scheme
rollback = \case
    Wallet _ pending _ :| Wallet utxo' pending' s' : checkpoints ->
        Wallet utxo' (pending <> pending') s' :| checkpoints
    checkpoints ->
        checkpoints


{-------------------------------------------------------------------------------
                             ADDRESS DERIVATION
--------------------------------------------------------------------------------}

-- We introduce some phantom types here to force disctinction between the
-- various key types we have; just to remove some confusion in type signatures
newtype Key (scheme :: Scheme) (level :: Depth) key = Key
    { getKey :: key }

keyToXPub :: Key scheme level XPrv -> Key scheme level XPub
keyToXPub (Key xprv) = Key (toXPub xprv)

-- Also introducing a type helper to distinguish between indexes
newtype Index (derivationType :: DerivationType) (level :: Depth) = Index
    { getIndex :: Word32
    }

data Scheme
    = Seq
    | Rnd

data Depth
    = Root0
    | Acct3
    | Addr5

data DerivationType
    = Hardened
    | Soft

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


-- * Random Derivation

deriveAccountPrivateKeyRnd
    :: ByteString -- Passphrase used to encrypt Master Private Key
    -> Key 'Rnd 'Root0 XPrv
    -> Index 'Hardened 'Acct3
    -> Key 'Rnd 'Acct3 XPrv
deriveAccountPrivateKeyRnd passPhrase (Key masterXPrv) (Index accIx) =
    Key $ deriveXPrv DerivationScheme1 passPhrase masterXPrv accIx

deriveAddressPrivateKeyRnd
    :: ByteString -- Passphrase used to encrypt Account Private Key
    -> Key 'Rnd 'Acct3 XPrv
    -> Index 'Soft 'Addr5
    -> Key 'Rnd 'Addr5 XPrv
deriveAddressPrivateKeyRnd passPhrase (Key accXPrv) (Index addrIx) =
    Key $ deriveXPrv DerivationScheme1 passPhrase accXPrv addrIx

rndToAddress
    :: Key 'Rnd 'Addr5 XPub
    -> Key 'Rnd 'Root0 XPub
    -> Index 'Hardened 'Acct3
    -> Index 'Soft 'Addr5
    -> Address
rndToAddress (Key addrXPub) rootKey (Index accIx) (Index addrIx) =
    Address $ CBOR.toStrictByteString $ encodeAddress addrXPub encodeAttributes
  where
    encodeAttributes = mempty
        <> CBOR.encodeMapLen 1
        <> CBOR.encodeWord8 1
        <> encodeDerivationPath (hdPassphrase rootKey) accIx addrIx

-- | Gotta love Serokell hard-coded nonce :) .. Kill me now.
cardanoNonce :: ByteString
cardanoNonce = "serokellfore"

-- | Simplified ChaChaPoly encryption used for encrypting the HD payload of addresses
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

hdPassphrase :: Key 'Rnd 'Root0 XPub -> ByteString
hdPassphrase (Key rootXPub) = PBKDF2.generate
    (PBKDF2.prfHMAC SHA512)
    (PBKDF2.Parameters 500 32)
    (unXPub rootXPub)
    ("address-hashing" :: ByteString)


-- * Sequential Derivation

purposeIndex :: Word32
purposeIndex = 0x8000002C

coinTypeIndex :: Word32
coinTypeIndex = 0x80000717

deriveAccountPrivateKeySeq
    :: ByteString -- Passphrase used to encrypt Master Private Key
    -> Key 'Seq 'Root0 XPrv
    -> Index 'Hardened 'Acct3
    -> Key 'Seq 'Acct3 XPrv
deriveAccountPrivateKeySeq passPhrase (Key masterXPrv) (Index accIx) =
    let -- lvl1 derivation in bip44 is hardened derivation of purpose' chain
        purposeXPrv = deriveXPrv DerivationScheme2 passPhrase masterXPrv purposeIndex
        -- lvl2 derivation in bip44 is hardened derivation of coin_type' chain
        coinTypeXPrv = deriveXPrv DerivationScheme2 passPhrase purposeXPrv coinTypeIndex
        -- lvl3 derivation in bip44 is hardened derivation of account' chain
        acctXPrv = deriveXPrv DerivationScheme2 passPhrase coinTypeXPrv accIx
    in
        Key acctXPrv

deriveAddressPrivateKeySeq
    :: ByteString -- Passphrase used to encrypt Account Private Key
    -> Key 'Seq 'Acct3 XPrv
    -> ChangeChain
    -> Index 'Soft 'Addr5
    -> Key 'Seq 'Addr5 XPrv
deriveAddressPrivateKeySeq passPhrase (Key accXPrv) changeChain (Index addrIx) =
    let -- lvl4 derivation in bip44 is derivation of change chain
        changeXPrv = deriveXPrv DerivationScheme2 passPhrase accXPrv (fromIntegral $ fromEnum changeChain)
        -- lvl5 derivation in bip44 is derivation of address chain
        addrXPrv = deriveXPrv DerivationScheme2 passPhrase changeXPrv addrIx
    in
        Key addrXPrv

deriveAddressPublicKeySeq
    :: Key 'Seq 'Acct3 XPub
    -> ChangeChain
    -> Index 'Soft 'Addr5
    -> Maybe (Key 'Seq 'Addr5 XPub)
deriveAddressPublicKeySeq (Key accXPub) changeChain (Index addrIx) = do
    -- lvl4 derivation in bip44 is derivation of change chain
    changeXPub <- deriveXPub DerivationScheme2 accXPub (fromIntegral $ fromEnum changeChain)
    -- lvl5 derivation in bip44 is derivation of address chain
    addrXPub <- deriveXPub DerivationScheme2 changeXPub addrIx
    return $ Key addrXPub

seqToAddress
    :: Key 'Seq 'Addr5 XPub
    -> Address
seqToAddress (Key xpub) =
    Address $ CBOR.toStrictByteString $ encodeAddress xpub encodeAttributes
  where
    encodeAttributes = mempty <> CBOR.encodeMapLen 0


{-------------------------------------------------------------------------------
                             ADDRESS DISCOVERY
--------------------------------------------------------------------------------}

class IsOurs (scheme :: Scheme) where
    type SchemeState scheme :: *
    addressIsOurs
        :: Proxy scheme
        -> Address
        -> SchemeState scheme
        -> (Bool, SchemeState scheme)


-- * Random Derivation

instance IsOurs 'Rnd where
    type SchemeState 'Rnd = ByteString
    addressIsOurs _ (Address bytes) passphrase =
        let
            payload = unsafeDeserialiseFromBytes decodeAddressPayload (BL.fromStrict bytes)
        in
        case unsafeDeserialiseFromBytes (decodeAddressDerivationPath passphrase) (BL.fromStrict payload) of
            Just (_, _) -> (True, passphrase)
            _           -> (False, passphrase)


-- * Sequential Derivation

data AddressPool = AddressPool
    { accountPubKey
        :: Key 'Seq 'Acct3 XPub
    , gap
        :: Word8
    , changeChain
        :: ChangeChain
    , addresses
        :: Map Address (Index 'Soft 'Addr5)
    } deriving (Generic)

lookupAddressPool
    :: Address
    -> AddressPool
    -> (Maybe (Address, Index 'Soft 'Addr5), AddressPool)
lookupAddressPool target pool =
    case Map.lookup target (pool ^. #addresses) of
        Just ix ->
            (Just (target, ix), extendAddressPool ix pool)
        Nothing ->
            (Nothing, pool)

extendAddressPool
    :: Index 'Soft 'Addr5
    -> AddressPool
    -> AddressPool
extendAddressPool (Index ix) pool
    | isOnEdge  = pool & #addresses %~ (next <>)
    | otherwise = pool
  where
    edge = Map.size (pool ^. #addresses)
    isOnEdge = fromIntegral edge - ix <= fromIntegral (pool ^. #gap)
    next = nextAddresses
        (pool ^. #accountPubKey)
        (pool ^. #gap)
        (pool ^. #changeChain)
        (Index $ ix + 1)

nextAddresses
    :: Key 'Seq 'Acct3 XPub
    -> Word8
    -> ChangeChain
    -> Index 'Soft 'Addr5
    -> Map Address (Index 'Soft 'Addr5)
nextAddresses key g changeChain (Index fromIx) =
    invariant safeNextAddresses "nextAddresses: toIx should be greater than fromIx" (toIx >= fromIx)
  where
    safeNextAddresses = [fromIx .. toIx]
        & map (\ix -> (newAddress (Index ix), Index ix))
        & Map.fromList
    toIx = fromIx + fromIntegral g - 1
    newAddress ix =
        let
            addr = deriveAddressPublicKeySeq key changeChain ix
        in
            invariant
                (seqToAddress $ fromJust addr)
                "nextAddresses: can't generate more addresses, max index reached"
                (isJust addr)

instance IsOurs 'Seq where
    type SchemeState 'Seq = AddressPool
    addressIsOurs _ addr = runState $ do
        maddr <- state $ lookupAddressPool addr
        return $ case maddr of
            Just (_, Index ix) -> traceShow ix True
            Nothing            -> False


{-------------------------------------------------------------------------------
                              NETWORK LAYER

  A very simple networking stack that assumes that there's the cardano-http-bridge
  running on port 1337. We define here a small interface as the 'NetworkLayer'
  so in theory, anything implementing that interface would work with the rest of
  the code.
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

    A 16-byte header also prefixes all epoch, it contains:

      * An 8-byte 'magic' string
      * A 4-byte file-type, set to "PACK"
      * A 4-byte version number, set to 1 at the moment

    Then, each block is encoded as:
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
                -- complexity. So we better prepend elements and reverse the list
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
    -- Treating addresses as a blob here, so we just ree-ncode them as such
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

-- This only makes sense for addresses in the Random scheme; The sequential
-- scheme has no derivation path and no address payload so-to-speak. So this
-- will just return 'Nothing' for seq addresses.
decodeAddressDerivationPath :: ByteString -> CBOR.Decoder s (Maybe (Word32, Word32))
decodeAddressDerivationPath passphrase = do
    _ <- CBOR.decodeListLenCanonicalOf 3
    _ <- CBOR.decodeBytes
    l <- CBOR.decodeMapLen
    case l of
        1 -> do
            _ <- CBOR.decodeWord8
            bytes <- unsafeDeserialiseFromBytes CBOR.decodeBytes . BL.fromStrict <$> CBOR.decodeBytes
            case decryptDerPath passphrase bytes of
                CryptoFailed _ ->
                    return Nothing
                CryptoPassed moarBytes -> do
                    let (Right (_, result)) = CBOR.deserialiseFromBytes decodeDerPath (BL.fromStrict moarBytes)
                    return result
        _ ->
            return Nothing
  where
    decodeDerPath :: CBOR.Decoder s (Maybe (Word32, Word32))
    decodeDerPath = do
        path <- decodeListIndef CBOR.decodeWord32
        case path of
            [accIx, addrIx] -> return $ Just (accIx, addrIx)
            _               -> return Nothing

decodeAddressPayload :: CBOR.Decoder s ByteString
decodeAddressPayload = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    _ <- CBOR.decodeTag
    bytes <- CBOR.decodeBytes
    _ <- CBOR.decodeWord32 -- CRC
    return bytes

decodeAttributes :: CBOR.Decoder s ((), CBOR.Encoding)
decodeAttributes = do
    _ <- CBOR.decodeMapLenCanonical -- Empty map of attributes
    return ((), CBOR.encodeMapLen 0)

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
            -- In theory, we should also:
            --
            -- _ <- decodeGenesisBlockBody
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
    return
        ( Tx (Set.fromList inputs) (Map.fromList (zip [0..] outputs))
        , TxWitness
        )

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
            tag <- CBOR.decodeTag
            bytes <- CBOR.decodeBytes
            case CBOR.deserialiseFromBytes decodeTxIn' (BL.fromStrict bytes) of
                Left err         -> fail $ show err
                Right (_, input) -> return input
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
                              CBOR ENCODERS

    Ideally at some point, we do want roundtrip tests between encoders and
    decoders ...
--------------------------------------------------------------------------------}

encodeAddress :: XPub -> CBOR.Encoding -> CBOR.Encoding
encodeAddress (XPub pub (ChainCode cc)) encodeAttributes =
    encodeAddressPayload payload
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

    encodeXPub =
        CBOR.encodeBytes (pub <> cc)

    encodeSpendingData = CBOR.encodeListLen 2
        <> CBOR.encodeWord8 0
        <> encodeXPub

encodeAddressPayload :: ByteString -> CBOR.Encoding
encodeAddressPayload payload = mempty
    <> CBOR.encodeListLen 2
    <> CBOR.encodeTag 24 -- Hard-Coded Tag value in cardano-sl
    <> CBOR.encodeBytes payload
    <> CBOR.encodeWord32 (crc32 payload)

encodeAttributes :: CBOR.Encoding
encodeAttributes = mempty
    <> CBOR.encodeMapLen 0

encodeDerivationPath :: ByteString -> Word32 -> Word32 -> CBOR.Encoding
encodeDerivationPath passphrase accIx addrIx =
    let
        path = CBOR.toStrictByteString $ mempty
            <> CBOR.encodeListLenIndef
            <> CBOR.encodeWord32 accIx
            <> CBOR.encodeWord32 addrIx
            <> CBOR.encodeBreak
    in
        case encryptDerPath passphrase path of
            CryptoPassed a ->
                CBOR.encodeBytes $ CBOR.toStrictByteString $ CBOR.encodeBytes a
            CryptoFailed e ->
                error $ "encodeDerivationPath : " <> show e

encodeTx :: Tx -> CBOR.Encoding
encodeTx tx = mempty
    <> CBOR.encodeListLen 3
    <> CBOR.encodeListLenIndef
    <> mconcat (encodeTxIn <$> Set.toList (inputs tx))
    <> CBOR.encodeBreak
    <> CBOR.encodeListLenIndef
    <> mconcat (encodeTxOut <$> Map.elems (outputs tx))
    <> CBOR.encodeBreak
    <> encodeAttributes

encodeTxIn :: TxIn -> CBOR.Encoding
encodeTxIn (TxIn (TxId txid) ix) = mempty
    <> CBOR.encodeListLen 2
    <> CBOR.encodeWord8 0
    <> CBOR.encodeTag 24
    <> CBOR.encodeBytes bytes
  where
    bytes = CBOR.toStrictByteString $ mempty
        <> CBOR.encodeListLen 2
        <> CBOR.encodeBytes txid
        <> CBOR.encodeWord32 ix

encodeTxOut :: TxOut -> CBOR.Encoding
encodeTxOut (TxOut (Address addr) (Coin coin)) = mempty
    <> CBOR.encodeListLen 2
    <> encodeAddressPayload payload
    <> CBOR.encodeWord64 coin
  where
    payload = unsafeDeserialiseFromBytes decodeAddressPayload (BL.fromStrict addr)


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

prettyPrint :: ToJSON a => a -> IO ()
prettyPrint =
    BL8.putStrLn . Aeson.encodePretty


{-------------------------------------------------------------------------------
                                   TESTING

  A bit of testing to compare this prototype implementation with the existing
  code on cardano-sl. It doesn't do much but at least, make sure that we
  generate and encode addresses correctly, comparing to what's on cardano-sl
  and cardano-wallet already.
--------------------------------------------------------------------------------}

syncWithMainnet :: NetworkLayer -> IO [[Block]]
syncWithMainnet network = timed "Sync With Mainnet" $ do
    tip <- getNetworkTip network
    traverse (getEpoch network) [95..(fromIntegral (epochIndex tip) - 1)]

restoreDaedalusWallet :: [[Block]] -> IO [Address]
restoreDaedalusWallet epochs = timed "Restore Daedalus Wallet" $ do
    let addresses = epochs
            & mconcat
            & concatMap (Set.toList . transactions)
            & concatMap (Map.elems . outputs)
            & map address
    let isOurs = fst . flip (addressIsOurs (Proxy @Rnd)) (hdPassphrase $ keyToXPub daedalusXPrv)
    return $ filter isOurs addresses

restoreYoroiWallet :: [[Block]] -> IO [Address]
restoreYoroiWallet epochs = timed "Restore Yoroi Wallet" $ do
    let addresses = epochs
            & mconcat
            & concatMap (Set.toList . transactions)
            & concatMap (Map.elems . outputs)
            & map address

    let accKey = keyToXPub $ deriveAccountPrivateKeySeq mempty yoroiXPrv (Index 0x80000000)
    -- NOTE
    -- We have to scan both the internal and external chain. Note that, the
    -- account discovery algorithm is only specified for the external chain so
    -- in theory, there's nothing forcing a wallet to generate change
    -- addresses on the internal chain anywhere in the available range.
    --
    -- In practice, we may assume that user can't create change addresses and
    -- that they are just created in sequence by the wallet. Hence an address
    -- pool with a gap of 1 should be sufficient.
    let pool  = AddressPool accKey 20 ExternalChain (nextAddresses accKey 20 ExternalChain (Index 0))
    let pool' = AddressPool accKey 1 InternalChain (nextAddresses accKey 1 InternalChain (Index 0))
    let f addr = do
            ours <- state $ addressIsOurs (Proxy @Seq) addr
            return $ if ours then Just addr else Nothing
    let (addrs, _) = flip runState pool $ catMaybes <$> traverse f addresses
    let (addrs', _) = flip runState pool' $ catMaybes <$> traverse f addresses
    return $ addrs <> addrs'

runTests :: IO ()
runTests = do
    chachapolyRountrip
    addressGoldenTest

chachapolyRountrip :: IO ()
chachapolyRountrip = do
    let pw = BS.replicate 32 1 -- NOTE Password must be a 32-length key
    invariant (return ()) "ChaChaPoly RoundTrip" $
        (encryptDerPath pw "patate" >>= decryptDerPath pw) == return "patate"

addressGoldenTest :: IO ()
addressGoldenTest = do
    invariant (return ()) "Address Golden Test - Yoroi 0'/0/0" $
        toJSON (genYoroiAddr 0x80000000 0 ExternalChain) == toJSON ("Ae2tdPwUPEZLLeQYaBmNXiwrv9Mf13eauCxgHxZYF1EhDKMTKR5t1dFrSCU" :: String)

    invariant (return ()) "Address Golden Test - Yoroi 0'/1/0" $
        toJSON (genYoroiAddr 0x80000000 0 InternalChain) == toJSON ("Ae2tdPwUPEZ9qDt13UhqJmNUALW56V9KhErnTAMsUwV4qm33CzfEmLP3tfP" :: String)

    invariant (return ()) "Address Golden Test - Yoroi 0'/0/14" $
        toJSON (genYoroiAddr 0x80000000 14 ExternalChain) == toJSON ("Ae2tdPwUPEZ6JkktL91gdeAEZrwxVyDfxE5GTJ9LLCnogcpe3GPd48m4Fir" :: String)

    invariant (return ()) "Address Golden Test - Yoroi 0'/1/14" $
        toJSON (genYoroiAddr 0x80000000 14 InternalChain) == toJSON ("Ae2tdPwUPEZEAgMFTZ3XvXupMJnbrKNxCtmBG4Ry4qBHYgCxe7T98fxr7uw" :: String)

    invariant (return ()) "Address Golden Test - Yoroi 14'/0/0" $
        toJSON (genYoroiAddr 0x8000000E 0 ExternalChain) == toJSON ("Ae2tdPwUPEZKCUMsknNU6FmV59dXGgHamS5cEfH6AR6u7bq5Y5RaneTBqBH" :: String)

    invariant (return ()) "Address Golden Test - Yoroi 14'/1/0" $
        toJSON (genYoroiAddr 0x8000000E 0 InternalChain) == toJSON ("Ae2tdPwUPEZ726BqcPdWdzSN42tPSu9Ryx4qEU9FBTLfBW8g5DU76FTn9Eo" :: String)

    invariant (return ()) "Address Golden Test - Yoroi 14'/0/42" $
        toJSON (genYoroiAddr 0x8000000E 42 ExternalChain) == toJSON ("Ae2tdPwUPEZGHqe3aWWBEGav6V6BuBZmB9XfQADZz6eagBaPZJCAtVrjXe2" :: String)

    invariant (return ()) "Address Golden Test - Yoroi 14'/1/42" $
        toJSON (genYoroiAddr 0x8000000E 42 InternalChain) == toJSON ("Ae2tdPwUPEZD6w2iqeQCyQt5dEhCnxwB5kooG8k2HhDoVc3myuHKWiD3fWi" :: String)

    invariant (return ()) "Address Golden Test - Daedalus 0'/0" $
        toJSON (genDaedalusAddr 0x80000000 0) == toJSON ("2w1sdSJu3GViq5Rx3xYMS8twmKen9tQNya7DqHfQPzg5f6Lc6EXpDKoWA3wjiUk6dvN8bnUHZfhcSTXxkyHqBnzv7M15w52xJbq" :: String)

    invariant (return ()) "Address Golden Test - Daedalus 0'/14" $
        toJSON (genDaedalusAddr 0x80000000 14) == toJSON ("2w1sdSJu3GVhSLVv1Yh7wmBT67tZ2KaXKEMFVUSy6rZnYbCJRjywkDSiU9ZZggvYSBK2hZ4C4MsaPwTJiKq99LvzYDmKgRgTBjF" :: String)

    invariant (return ()) "Address Golden Test - Daedalus 14'/0" $
        toJSON (genDaedalusAddr 0x8000000E 0) == toJSON ("2w1sdSJu3GVieSGggHVpLxhgeh8Kno7oaBPyTFiKYJejSAMQ3vv1j2Lsx2jSTnuRgVgXbwtbTUUUmqJtitTAoUXJxKgZKJaYxFr" :: String)

    invariant (return ()) "Address Golden Test - Daedalus 14'/42" $
        toJSON (genDaedalusAddr 0x8000000E 42) == toJSON ("9XQrTpiaBYn6K5uDNHphfxRXnGk3DMn7qDgxp2LditeMjueMhnYRmWmEbsUVsCodE3SJ6LQWzyVb51MYVp1pu2mAHJChz7UPJg4t" :: String)


genYoroiAddr :: Word32 -> Word32 -> ChangeChain -> Address
genYoroiAddr accIx addrIx changeChain =
    let
        acctXPrv = deriveAccountPrivateKeySeq mempty yoroiXPrv (Index accIx)
        addrXPrv = deriveAddressPrivateKeySeq mempty acctXPrv changeChain (Index addrIx)
    in
        seqToAddress (keyToXPub addrXPrv)

genDaedalusAddr :: Word32 -> Word32 -> Address
genDaedalusAddr accIx addrIx =
    let
        acctXPrv = deriveAccountPrivateKeyRnd mempty daedalusXPrv (Index accIx)
        addrXPrv = deriveAddressPrivateKeyRnd mempty acctXPrv (Index addrIx)
    in
        rndToAddress (keyToXPub addrXPrv) (keyToXPub daedalusXPrv) (Index accIx) (Index addrIx)

-- | A root private key using the sequential scheme on MAINNET.
-- Kindly by Patrick from QA.
yoroiXPrv :: Key 'Seq 'Root0 XPrv
yoroiXPrv = Key $ generateNew @ByteString @ByteString @ByteString
    "v\190\235Y\179#\181s]M\214\142g\178\245\DC4\226\220\f\167"
    mempty
    mempty

-- | A root private key using the random scheme on MAINNET.
-- Kindly provided by Alan from QA.
daedalusXPrv :: Key 'Rnd 'Root0 XPrv
daedalusXPrv = Key $ generate @ByteString @ByteString
    "X >\178\ETB\DLE\GSg\226\192\198z\131\189\186\220(A+\247\204h\253\235\&5\SUB\CAN\176g\223\212c|f"
    mempty
