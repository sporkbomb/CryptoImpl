-- A ARCFOUR-dropN implementation in Haskell with adjustable S-box size.
-- Does not clear key material from memory. Also, I don't know crypto. Don't use this in production.

--Copyright (c) 2012, sporkbomb/sp0rkbomb/__sporkbomb
--All rights reserved.

--Redistribution and use in source and binary forms, with or without
--modification, are permitted provided that the following conditions are met: 
--
--1. Redistributions of source code must retain the above copyright notice, this
--   list of conditions and the following disclaimer. 
--2. Redistributions in binary form must reproduce the above copyright notice,
--   this list of conditions and the following disclaimer in the documentation
--   and/or other materials provided with the distribution. 
--
--THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
--ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
--WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
--DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
--ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
--(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
--LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
--ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
--(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
--SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import Data.Word
import Data.Bits
import qualified Data.ByteString as B
import System( getArgs )
import System.IO

-- Set this to Word16, Word32 etc to get a much larger S-box size.
-- Of course, this also increases processing cost.
type Base = Word8

-- This is, by default, essentially the same as a ByteString.
-- But it can also be a WordString or DWordString, so let's just call it BString.
type BString = [Base]

-- The RC4 state at any given point.
-- The BString is the S-Box, the two Bases are indices i and j respectively.
data State = State BString Base Base deriving (Show)
--                      S   i    j

-- We're not doing plain RC4, but actually RC4-drop-$n, where $n is the number specified here.
-- The reason for this is the Fluhrer/Martin/Shamir attack, see https://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack
-- We simply discard the initial `dropN` values from the keystream.
dropN :: Int
dropN = 3072

-- This is the number of values that can be expressed using `Base`, i.e. 2^(number-of-bits-in-Base) 
size :: Int
size = 2^(bitSize (0::Base))

-- The main {de,en}crypt function. Derives the key and message from the parameters and returns the encrypted/decrypted value.
crypt :: B.ByteString -> [Char] -> BString
crypt msgStr keyStr = crypt' state msg
                      where msg = map fromIntegral $ map fromEnum (B.unpack msgStr) :: [Base]
                            key = map fromIntegral $ map fromEnum keyStr :: [Base]
                            state = keySetup key

-- The internal worker for `crypt`. Recurses over input values and XOR's them with one value from the keystream. 
crypt' :: State -> BString -> BString
crypt' _ []          = []
crypt' state (m:msg) = e : (crypt' state' msg)
                       where (state',k) = next state
                             e = m `xor` k

-- Key setup function. Initialises the S-Box and drops the first `dropN` values from the keystream.
-- The parts used to derive the key are:
--     A list of length `size` from 0 to `size`
--     A second list of length `size` created by cycling the passphrase
keySetup :: BString -> State
keySetup key = dropKeystream (State (initSBox s s2) 0 0) dropN
               where s = take size [0..]::[Base]
                     s2 = take size $ cycle key::[Base]

-- Simply generates and discards the given number of keystream values.
dropKeystream :: State -> Int -> State
dropKeystream state skip = if (skip==0) then state
                            else dropKeystream state' (skip-1)
			    where (state',k) = next state

-- Generates the next value in the keystream.
-- According to standard, this is the following operation:
-- j+=S[++i]; // Though you'll have to `mod` i and j by `size` if the data type is larger. But it isn't in this implementation.
-- t=S[i]+S[j]; // Same
-- acc=S[i];S[i]=S[j];S[j]=acc; // Swap
-- k=S[t];
next :: State -> (State,Base)
next (State key i j)  = ((State key' i' j'),k)
           where i'   = i+1
                 j'   = j+(key!!(fromEnum i'))
                 si   = key!!(fromEnum i')
                 sj   = key!!(fromEnum j')
                 key' = substitute (State key i' j')
                 t    = fromEnum $ (si+sj)
                 k    = key'!!t

-- Initialise the S-Box (s) as described in the standard (see below)
initSBox :: BString -> BString -> BString
initSBox s s2 = initSBox' s2 (State s 0 0)

-- The actual S-Box initialisation happens here.
-- It works as follows:
-- Iterate over all possible values for i, starting from 0
-- 	j+=S[i]+S2[i] // mod `size`, but that's irrelevant here
-- 	acc=S[i];S[i]=S[j];S[j]=acc; // Swap
--
-- After this, you should discard s2, zero out i and j and clear any remaining key material.
-- But try telling that to a Haskell runtime.
initSBox' :: BString -> State -> BString
initSBox' s2 (State s i j) = if(0==complement i) then s' else initSBox' s2 (State s' (i+1) j')
                     where j' = (j + s!!(fromEnum i) + s2!!(fromEnum i))
		           s' = substitute (State s i j')

-- Ugly-as-sin helper function that simply swaps the values at indices i and j.
-- In other words: acc=S[i];S[i]=S[j];S[j]=acc;
substitute :: State -> BString
substitute (State s i j) = s'
                         where s' = left ++ (rsub : center) ++ (lsub : right)
                               lcut = fromEnum $ min i j
                               lsub = s!!lcut
                               rcut = fromEnum $ max i j
                               rsub = s!!rcut
                               left = take lcut s
                               center = take (rcut-lcut-1) $ drop (lcut+1) s
                               right = drop (rcut+1) s

-- IO. Non-purity goes here.
main = do
       (keyStr:_) <- getArgs
       input <- B.hGetContents stdin
       B.hPut stdout $ B.pack $ crypt input keyStr
