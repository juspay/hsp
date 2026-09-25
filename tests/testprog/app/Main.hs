{-# LANGUAGE BangPatterns #-}
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
-- Every thread is labelled with GHC.Conc.labelThread, so the sampler's label
-- read is exercised.  Results are printed, so the optimiser cannot drop the
-- work.
module Main (main) where

import Control.Concurrent
import Control.Monad
import Data.IORef
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

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  args <- getArgs
  case args of
    ["requests", n] -> requests (read n)
    ["smoke", s] -> smoke (read s)
    [s] -> smoke (read s)
    _ -> smoke 3
