{-# LANGUAGE BangPatterns        #-}
{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import qualified Codec.CBOR.Decoding        as CBOR
import qualified Codec.CBOR.Encoding        as CBOR
import qualified Codec.CBOR.Read            as CBOR
import qualified Codec.CBOR.Write           as CBOR
import           Control.Arrow              (first)
import           Control.DeepSeq            (NFData, deepseq)
import           Control.Monad              (void)
import           Control.Monad.State.Strict (State, evalState, get, modify,
                                             state)
import           Data.Aeson                 (ToJSON (..))
import qualified Data.Aeson                 as Aeson
import qualified Data.Aeson.Encode.Pretty   as Aeson
import           Data.Bits                  (shiftL, (.|.))
import           Data.ByteString            (ByteString)
import qualified Data.ByteString.Base16     as B16
import           Data.ByteString.Base58     (bitcoinAlphabet, encodeBase58)
import qualified Data.ByteString.Char8      as BS
import qualified Data.ByteString.Lazy       as BL
import qualified Data.ByteString.Lazy.Char8 as BL8
import           Data.Int                   (Int64)
import qualified Data.Text.Encoding         as T
import           Data.Time.Clock            (diffUTCTime, getCurrentTime)
import           Data.Word                  (Word16, Word32, Word64)
import           Debug.Trace                (traceShow)
import           GHC.Generics               (Generic)
import           Network.HTTP.Client        (Manager, defaultRequest, httpLbs,
                                             path, port, responseBody,
                                             responseStatus)
import qualified Network.HTTP.Client        as HTTP

main :: IO ()
main = timed $ do
    net <- newNetworkLayer
    epochs  <- traverse (getEpoch net) [0..9]
    print $ length epochs


{-------------------------------------------------------------------------------
                            PRIMITIVE TYPES
--------------------------------------------------------------------------------}

data Block = Block
    { header       :: !BlockHeader
    , transactions :: [Tx]
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
    { inputs  :: [TxInput]
    , outputs :: [TxOutput]
    } deriving (Show, Generic)

instance NFData Tx

instance ToJSON Tx where
    toJSON = Aeson.genericToJSON Aeson.defaultOptions


newtype Address = Address
    { getAddress :: ByteString
    } deriving (Show, Generic)

instance NFData Address

instance ToJSON Address where
    toJSON = Aeson.String . T.decodeUtf8 . encodeBase58 bitcoinAlphabet . getAddress


newtype TxId = TxId
    { getTxId :: ByteString
    } deriving (Show, Generic)

instance NFData TxId

instance ToJSON TxId where
    toJSON = Aeson.String . T.decodeUtf8 . B16.encode . getTxId

data TxInput = TxInput
    { txId    :: !TxId
    , txIndex :: !Word32
    } deriving (Show, Generic)

instance NFData TxInput

instance ToJSON TxInput where
    toJSON = Aeson.genericToJSON Aeson.defaultOptions


data TxOutput = TxOutput
    { address :: !Address
    , coin    :: !Word64
    } deriving (Show, Generic)

instance NFData TxOutput

instance ToJSON TxOutput where
    toJSON = Aeson.genericToJSON Aeson.defaultOptions


data TxWitness = TxWitness deriving (Show)


{-------------------------------------------------------------------------------
                              NETWORK LAYER
--------------------------------------------------------------------------------}

data NetworkLayer = NetworkLayer
    { getBlock :: BlockHeaderHash -> IO Block
    , getEpoch :: Int -> IO [Block]
    }


mkNetworkLayer :: Manager -> NetworkLayer
mkNetworkLayer manager = NetworkLayer
    { getBlock = _getBlock manager
    , getEpoch = _getEpoch manager
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
    let (Right (_, block)) = CBOR.deserialiseFromBytes decodeBlock $ responseBody res
    return $ block `deepseq` block


_getEpoch :: Manager -> Int -> IO [Block]
_getEpoch manager n = do
    let req = defaultRequest
            { port = 1337
            , path = "/mainnet/epoch/" <> BS.pack (show n)
            }
    res <- httpLbs req manager
    let epoch = deserialiseEpoch decodeBlock (responseBody res)
    return $ epoch `deepseq` epoch


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
            -- for the wallet backend.
            drop 1 (reverse epoch)
        | otherwise =
            let
                (size, r0) =
                    first (fromIntegral . word32) $ BL.splitAt 4 bytes

                (blkBytes, r1) =
                    BL.splitAt size r0

                (Right (_, block)) =
                    CBOR.deserialiseFromBytes decodeBlock blkBytes
            in
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
    crc <- CBOR.decodeWord -- CRC
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
        <> CBOR.encodeWord crc

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
            -- _ <- decodeGenesisBlockBody
            return $ Block header []

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

decodeMainBlockBody :: CBOR.Decoder s [Tx]
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
    inputs <- decodeListIndef decodeTxInput
    outputs <- decodeListIndef decodeTxOutput
    _ <- decodeAttributes
    _ <- decodeList decodeTxWitness
    return (Tx inputs outputs, TxWitness)

decodeTxPayload :: CBOR.Decoder s [Tx]
decodeTxPayload = do
    (txs, _) <- unzip <$> decodeListIndef decodeTx
    return txs

decodeTxInput :: CBOR.Decoder s TxInput
decodeTxInput = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    t <- CBOR.decodeWord8
    case t of
        0 -> do
            _ <- CBOR.decodeTag
            bytes <- CBOR.decodeBytes
            case CBOR.deserialiseFromBytes decodeTxInput' (BL.fromStrict bytes) of
                Right (_, input) -> return input
                Left err         -> fail $ show err
        _ -> fail $ "decodeTxInput: unknown tx input constructor: " <> show t
  where
    decodeTxInput' :: CBOR.Decoder s TxInput
    decodeTxInput' = do
        _ <- CBOR.decodeListLenCanonicalOf 2
        txId <- CBOR.decodeBytes
        index <- CBOR.decodeWord32
        return $ TxInput (TxId txId) index

decodeTxOutput :: CBOR.Decoder s TxOutput
decodeTxOutput = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    addr <- decodeAddress
    coin <- CBOR.decodeWord64
    return $ TxOutput addr coin

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
    CBOR.decodeSequenceLenN (\xs x -> xs ++ [x]) [] id l decodeOne

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
    CBOR.decodeSequenceLenIndef (\xs x -> xs ++ [x]) [] id decodeOne


{-------------------------------------------------------------------------------
                                   UTILS

  Project various utils unrelated to any particular business logic.
--------------------------------------------------------------------------------}

timed :: IO () -> IO ()
timed io = do
    start <- getCurrentTime
    io
    getCurrentTime >>= \end -> print (diffUTCTime end start)
