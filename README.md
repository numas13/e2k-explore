# About

Simple program to show syllables in E2K executables and binaries.

# Disclaimer

I am not associated with MCST. I have no Elbrus CPU. The work was done with my assumptions based on analyzing
cross compiler output.

# Example

```
$ cat test.S
    .global _start
_start:
{
    ct %ctpr1
    fmul_adds,2,sm %b[54], _f32s,_lts0 0xdeadbeef, %b[17], %g8
}
$ lcc -mcpu=elbrus-v4 -c test.S -o test.o
$ cargo run -- dump test.o --disassemble
      Finished dev [unoptimized + debuginfo] target(s) in 0.06s
       Running `/home/denis/dev/e2k/target/debug/e2k-explore dump test.o --disassemble`
  0000000000000040 _start:
  
  ct %ctpr1
  ipd 3
  fmul_adds,2,sm %b[54], _f32s,_lts0 0xdeadbeef, %b[17], %g8
  
  00000040  23 10 40 10     HS 10401023
  00000044  20 04 00 c0     SS c0000420
  00000048  e8 d8 36 88   ALS2 8836d8e8
  0000004c  00 00 11 0c  ALES2 0c11     ALES5 0000
  00000050  00 00 00 00   LTS1 00000000
  00000054  ef be ad de   LTS0 deadbeef
```