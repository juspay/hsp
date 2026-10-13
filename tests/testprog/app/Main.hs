{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ForeignFunctionInterface #-}
-- | A GHC program with a known shape, for hsp's live tests.  Depends on base
-- only.  Two modes:
--
-- @hsp-testprog SECS@ (or @hsp-testprog smoke SECS@): three regions, each a
-- NOINLINE function, run one after another on labelled green threads for
-- about SECS seconds each:
--
--   allocy   allocates a list per iteration (allocation counter moves;
--            update frames with thunks on the stack)
--   chatty   a parent calling a small child millions of times: the child
--            is the leaf, the parent must be on the stack above it
--   deep     recursion 300 frames deep before doing work: the walk must
--            cross that depth and reach STOP_FRAME
--
-- @hsp-testprog requests N@: N "requests", four at a time.  Each runs on a
-- green thread labelled @rid:req-<i>@ (the convention a web framework would
-- use: the request id in the thread label), does an amount of work that
-- varies with i, and forks one child labelled @rid:req-<i>|fork:bg@.  Each
-- request prints its own exact allocation from the thread's allocation
-- counter (System.Mem.getAllocationCounter):
--
--   request req-<i> alloc_bytes <n>
--
-- so a test can compare what the sampler attributes to each label against
-- what the thread itself counted.
--
-- @hsp-testprog ffi SECS@: time spent in C, which must still be billed to the
-- green thread that called it.  Three regions of about SECS seconds each:
--
--   rid:unsafe   an unsafe foreign call into a busy C function that
--                overwrites r13 and r12 (BaseReg and Hp), as optimised C does
--   rid:safe     a safe foreign call into a busy C function, while a second
--                thread (rid:other) runs Haskell code on the capability the
--                call released
--   rid:memset   an unsafe call to libc's memset over a large buffer: the
--                leaf is in a shared library, outside the executable
--
-- Every thread is labelled with GHC.Conc.labelThread, so the sampler's label
-- read is exercised.  Results are printed, so the optimiser cannot drop the
-- work.
module Main (main) where

import Control.Concurrent
import Control.Monad
import Data.IORef
import Data.Word (Word8)
import Foreign.C.Types
import Foreign.Marshal.Alloc (free, mallocBytes)
import Foreign.Ptr (Ptr)
import GHC.Conc (labelThread)
import System.Environment
import System.IO
import System.Mem (getAllocationCounter, setAllocationCounter)

{-# NOINLINE allocy #-}
allocy :: Int -> Int
allocy n = sum (map (* 3) [1 .. n `mod` 97 + 5])

{-# NOINLINE child #-}
child :: Int -> Int
child x = (x * 1103515245 + 12345) `mod` 2147483647

{-# NOINLINE chatty #-}
chatty :: Int -> Int -> Int
chatty 0 acc = acc
chatty k acc = chatty (k - 1) (child acc)

{-# NOINLINE deep #-}
deep :: Int -> Int -> Int
deep 0 acc = chatty 2000 acc
deep k acc = 1 + deep (k - 1) (acc + k)

region :: String -> (Int -> Int) -> Double -> IO Int
region name f secs = do
  done <- newEmptyMVar
  ref <- newIORef False
  _ <- forkIO $ do
    me <- myThreadId
    labelThread me ("rid:" ++ name)
    let loop !i !acc = do
          stop <- readIORef ref
          if stop then putMVar done acc else loop (i + 1) (f (acc + i))
    loop (0 :: Int) 0
  threadDelay (round (secs * 1e6))
  writeIORef ref True
  takeMVar done

smoke :: Double -> IO ()
smoke secs = do
  a <- region "allocy" allocy secs
  b <- region "chatty" (chatty 5000) secs
  c <- region "deep" (deep 300) secs
  putStrLn ("smoke done " ++ show (a + b + c))

-- | Allocates for real: `reverse' is not a fusion producer, so the reversed
-- list's cons cells (and boxed Ints) are built on the heap every call.
-- (`allocy' above fuses into a loop once its result is unboxed.)
{-# NOINLINE listy #-}
listy :: Int -> Int
listy x = sum (reverse [x .. x + 40])

-- | A request's work: proportional to units, alternating an allocating step
-- and a call-heavy one (~1.6 KB allocated per step, ~250 MB per unit).
{-# NOINLINE work #-}
work :: Int -> Int -> Int
work units seed = go (units * 160000) seed
  where
    go 0 !acc = acc
    go k !acc = go (k - 1) (listy (acc `mod` 1000003 + k) + child acc)

-- | One request: work that varies with i (so requests differ in cost), plus
-- a forked child that allocates.  Reports the request thread's own
-- allocation; the child's is not included, as a service's per-request
-- counter would not include it either.
request :: Int -> IO Int
request i = do
  me <- myThreadId
  let rid = "req-" ++ show i
  labelThread me ("rid:" ++ rid)
  setAllocationCounter 0
  childDone <- newEmptyMVar
  _ <- forkIO $ do
    c <- myThreadId
    labelThread c ("rid:" ++ rid ++ "|fork:bg")
    let !r = work 1 (i * 7)
    putMVar childDone r
  let !r = work (i `mod` 5 + 1) i
  rc <- takeMVar childDone
  used <- getAllocationCounter
  putStrLn ("request " ++ rid ++ " alloc_bytes " ++ show (negate used))
  pure (r + rc)

requests :: Int -> IO ()
requests n = do
  total <- newIORef (0 :: Int)
  sem <- newQSem 4
  dones <- forM [1 .. n] $ \i -> do
    waitQSem sem
    d <- newEmptyMVar
    _ <- forkIO $ do
      r <- request i
      atomicModifyIORef' total (\t -> (t + r, ()))
      signalQSem sem
      putMVar d ()
    pure d
  mapM_ takeMVar dones
  t <- readIORef total
  putStrLn ("requests done " ++ show t)

foreign import ccall unsafe "hsp_busy_unsafe" c_busy_unsafe :: CLong -> IO CLong
foreign import ccall safe "hsp_busy_safe" c_busy_safe :: CLong -> IO CLong
foreign import ccall unsafe "string.h memset" c_memset :: Ptr Word8 -> CInt -> CSize -> IO (Ptr Word8)

-- | Run a labelled thread that repeats an action until told to stop.
labelled :: String -> IORef Bool -> IO Int -> IO (MVar Int)
labelled name stop act = do
  done <- newEmptyMVar
  _ <- forkIO $ do
    me <- myThreadId
    labelThread me ("rid:" ++ name)
    let loop !acc = do
          s <- readIORef stop
          -- yield: a loop of foreign calls allocates nothing, so the timer
          -- alone would never take the capability away from it
          if s then putMVar done acc else act >>= \r -> yield >> loop (acc + r)
    loop 0
  pure done

-- | One region: the named threads run together for about secs seconds.
ffiRegion :: Double -> [(String, IO Int)] -> IO Int
ffiRegion secs ts = do
  stop <- newIORef False
  dones <- mapM (\(n, a) -> labelled n stop a) ts
  threadDelay (round (secs * 1e6))
  writeIORef stop True
  sum <$> mapM takeMVar dones

ffi :: Double -> IO ()
ffi secs = do
  let n = 2000000 :: CLong        -- about a millisecond of C per call
  a <- ffiRegion secs [("unsafe", fromIntegral <$> c_busy_unsafe n)]
  b <- ffiRegion secs [ ("safe", fromIntegral <$> c_busy_safe n)
                      , ("other", pure $! chatty 20000 1) ]
  let size = 64 * 1024 * 1024
  buf <- mallocBytes size
  c <- ffiRegion secs [("memset", c_memset buf 1 (fromIntegral size) >> pure 1)]
  free buf
  putStrLn ("ffi done " ++ show (a + b + c))

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  args <- getArgs
  case args of
    ["requests", n] -> requests (read n)
    ["smoke", s] -> smoke (read s)
    ["ffi", s] -> ffi (read s)
    [s] -> smoke (read s)
    _ -> smoke 3
