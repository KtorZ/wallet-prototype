{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}

module Main where

import           Control.Monad        (void)

import qualified Codec.CBOR.Decoding  as CBOR
import qualified Codec.CBOR.Read      as CBOR
import           Data.ByteString.Lazy (ByteString)
import           Data.Word            (Word16, Word64)
import           Network.HTTP.Client  (defaultRequest, httpLbs, path, port,
                                       responseBody)
import qualified Network.HTTP.Client  as HTTP

import           Debug.Trace          (traceShow)

main :: IO ()
main = do
  manager <- HTTP.newManager HTTP.defaultManagerSettings
  let req = defaultRequest
        { port = 1337
        , path = "/mainnet/block/dd458ad4e1a2dff75c1d3f37704ba505405b12bdd28ed13a547c7467c87ff6a5"
        }
  response <- httpLbs req manager
  print response
  -- let bytes :: ByteString
  --     bytes = "\130\SOH\133\SUB-\150J\tX $\132\SUB\SOH\v$\177\EOTZ\148\255`W\155\138\229T\EOT\214\136\141\183X'\133s\176\250\143\233\DC4\224\132\131\SOHX \194B\DC4\n\228\NUL\191\157y\171=p\136A0\165\190\210\ACK\169\210\159r\DC1\234\218\ESC\SO\195\&4\ACKDX \165\134\GS\t\166R\238\213\&9\240;\154\221\\\201f\DLEP^y\155\234\146\200_\227\238\249\DC3\235\RS8\131\STXX \211j&\EM\166rIF\EOT\225\ESC\180G\203\207R1\233\242\186%\194\SYN\145w\237\201A\189P\173lX \211j&\EM\166rIF\EOT\225\ESC\180G\203\207R1\233\242\186%\194\SYN\145w\237\201A\189P\173lX \175\192\218d\CAN;\242fO=N\236r8\213$\186`\DEL\174\234\178O\193\NUL\235\134\GS\186i\151\ESCX Nf(\f\217MY\DLEr4\155\236\n0\144\165:\169EV.\251m\b\213nSeK\SO@\152\132\130\CAN`\EMT_X@\153:\143\ENQm->P\176\172`\DC3\159\DLE\223\143\129#\213\247\196\129{@\218\194\181\221\138\169J\130\232Sh2\230\&1-\223\192x}{S\DLE\200\NAKeZ\218O\219\207k\DC2)}DX\236\204-\251\129\SUB\NUL\US\242\147\130\STX\130\132\NULX@\153:\143\ENQm->P\176\172`\DC3\159\DLE\223\143\129#\213\247\196\129{@\218\194\181\221\138\169J\130\232Sh2\230\&1-\223\192x}{S\DLE\200\NAKeZ\218O\219\207k\DC2)}DX\236\204-\251X@\137\194\159\140J\242{z\204\190X\151G\130\SOH4\235\186\161\202\243\206\148\146p\163\208\199\220\253T\ESC\GS\239\&2m.\240\219x\ETXA\201\226a\240H\144\205\238\241\249\201\159m\144\184\237\202}<\252\t\136X@Ik)\181\197~\138\199\207\252n\139^@\179\210`\228\a\173M\ty-\236\176\162-T\218\DEL\136(&V\136\161\138\161\165\199m\158tw\165\244\166PP\DC4\t\253\205\&8U\179\NUL\253.+\195\198\ENQX@G5\237%*\STX\171\224\132\EM\SO\175Q\SOHGI\SYN\ETX\ENQ}?\225w\RS\147\CAN\189\217\ENQ\224l\RShzD\133c\130\151K)\159r}1}L\196u%\252\t\EM\235\232\157\142\198\207\179\&0\251\233\ACK\132\131\NUL\STX\NUL\130jcardano-sl\SOH\160X K\169*\163 \198\n\204\154\215\185\166O.\218U\196\210\236(\230\EOT\250\241\134p\139O\fN\142\223"

  let bytes = responseBody response
  print $ CBOR.deserialiseFromBytes decodeBlock bytes


{-------------------------------------------------------------------------------
                                  TYPES
--------------------------------------------------------------------------------}

data BlockHeader = BlockHeader
    { epochIndex :: Word64
    , slotNumber :: Word16
    } deriving (Show)

data Block = Block
    { header       :: BlockHeader
    , transactions :: [Tx]
    } deriving (Show)

data Tx = Tx deriving (Show)


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


decodeBlock :: CBOR.Decoder s Block
decodeBlock = do
    CBOR.decodeListLenCanonicalOf 2
    t <- CBOR.decodeWordCanonical
    case t of
        0 -> do -- Genesis Block
            error "TODO: Genesis Block"

        1 -> do -- Main Block
            CBOR.decodeListLenCanonicalOf 3
            header <- decodeBlockHeader
            transactions <- decodeBlockBody
            _ <- decodeMainExtraData
            return $ Block header transactions

        _ -> do
            fail $ "decodeBlock: unknown block constructor: " <> show t


decodeBlockHeader :: CBOR.Decoder s BlockHeader
decodeBlockHeader = do
    CBOR.decodeListLenCanonicalOf 2
    t <- CBOR.decodeWordCanonical
    case t of
      0 -> do -- Genesis Block Header
        _ <- CBOR.decodeListLenCanonicalOf 3
        _ <- decodeGenesisProof
        epochIndex <- decodeGenesisConsensusData
        _ <- decodeGenesisExtraData
        return $ BlockHeader epochIndex 0
      1 -> do -- Main Block Header
        _ <- CBOR.decodeListLenCanonicalOf 5
        _ <- decodeProtocolMagic
        _ <- decodePreviousBlockHeader
        _ <- decodeMainProof
        (epochIndex, slotNumber) <- decodeMainConsensusData
        _ <- decodeMainExtraData
        return $ BlockHeader epochIndex slotNumber
      _ ->
        fail $ "decodeBlockHeader: unknown block header constructor: " <> show t

decodeCertificatesProof :: CBOR.Decoder s ()
decodeCertificatesProof = do
    _ <- CBOR.decodeBytes -- Vss Certificates Hash
    return ()

decodeCommitmentsProof :: CBOR.Decoder s ()
decodeCommitmentsProof = do
    _ <- CBOR.decodeBytes -- Commitments Hash
    _ <- CBOR.decodeBytes -- Vss Certificates Hash
    return ()

decodeGenesisProof :: CBOR.Decoder s ()
decodeGenesisProof = do
    _ <- CBOR.decodeBytes -- Slot Leaders Hash
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

decodeProxySKsProof :: CBOR.Decoder s ()
decodeProxySKsProof = do
    _ <- CBOR.decodeBytes -- Dlg Payload Hash
    return ()

decodeSharesProof :: CBOR.Decoder s ()
decodeSharesProof = do
    _ <- CBOR.decodeBytes -- Shares Hash
    _ <- CBOR.decodeBytes -- Vss Certificates Hash
    return ()

decodeTxProof :: CBOR.Decoder s ()
decodeTxProof = do
    CBOR.decodeListLenCanonicalOf 3
    _ <- CBOR.decodeWord32 -- Number
    _ <- CBOR.decodeBytes  -- Merkle Root Hash
    _ <- CBOR.decodeBytes  -- Witnesses Hash
    return ()

decodeUpdateProof :: CBOR.Decoder s ()
decodeUpdateProof = do
    _ <- CBOR.decodeBytes -- Update Hash
    return ()

decodeGenesisConsensusData :: CBOR.Decoder s Word64
decodeGenesisConsensusData = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    epochIndex <- CBOR.decodeWord64
    _ <- decodeDifficulty
    return epochIndex

decodeMainConsensusData :: CBOR.Decoder s (Word64, Word16)
decodeMainConsensusData = do
    _ <- CBOR.decodeListLenCanonicalOf 4
    slot <- decodeSlotId
    _ <- decodeLeaderKey
    _ <- decodeDifficulty
    _ <- decodeSignature
    return slot

decodeSlotId :: CBOR.Decoder s (Word64, Word16)
decodeSlotId = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    epochIndex <- CBOR.decodeWord64
    slotNumber <- CBOR.decodeWord16
    return (epochIndex, slotNumber)

decodeLeaderKey :: CBOR.Decoder s ()
decodeLeaderKey = do
    _ <- CBOR.decodeBytes
    return ()

decodeDifficulty :: CBOR.Decoder s ()
decodeDifficulty = do
    _ <- CBOR.decodeListLenCanonicalOf 1
    _ <- CBOR.decodeWord64
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

decodeLightIndex :: CBOR.Decoder s ()
decodeLightIndex = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    _ <- CBOR.decodeWord64 -- Epoch Index #1
    _ <- CBOR.decodeWord64 -- Epoch Index #2
    return ()

decodeHeavyIndex :: CBOR.Decoder s ()
decodeHeavyIndex = do
    _ <- CBOR.decodeWord64 -- Epoch Index
    return ()

decodeMainExtraData :: CBOR.Decoder s ()
decodeMainExtraData = do
    _ <- CBOR.decodeListLenCanonicalOf 4
    _ <- decodeBlockVersion
    _ <- decodeSoftwareVersion
    _ <- decodeAttributes
    _ <- decodeDataProof
    return ()

decodeGenesisExtraData :: CBOR.Decoder s ()
decodeGenesisExtraData = do
    _ <- decodeAttributes
    return ()

decodeBlockVersion :: CBOR.Decoder s ()
decodeBlockVersion = do
    _ <- CBOR.decodeListLenCanonicalOf 3
    _ <- CBOR.decodeWord16 -- Major
    _ <- CBOR.decodeWord16 -- Minor
    _ <- CBOR.decodeWord8  -- Patch
    return ()

decodeSoftwareVersion :: CBOR.Decoder s ()
decodeSoftwareVersion = do
    _ <- CBOR.decodeListLenCanonicalOf 2
    _ <- CBOR.decodeString -- Application Name
    _ <- CBOR.decodeWord32 -- Software Version
    return ()

decodeAttributes :: CBOR.Decoder s ()
decodeAttributes = do
    _ <- CBOR.decodeMapLenCanonical -- Empty map of attributes
    return ()

decodeDataProof :: CBOR.Decoder s ()
decodeDataProof = do
    _ <- CBOR.decodeBytes -- Proof Hash
    return ()

decodeProtocolMagic :: CBOR.Decoder s ()
decodeProtocolMagic = do
    _ <- CBOR.decodeInt32
    return ()

decodePreviousBlockHeader :: CBOR.Decoder s ()
decodePreviousBlockHeader = do
    _ <- CBOR.decodeBytes
    return ()
