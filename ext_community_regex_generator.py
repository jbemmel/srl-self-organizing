#!/usr/bin/python3

import re

def GenerateRegex( min: int, max: int ):
    output = ""
    strmax = f"{max}"
    print( list(enumerate( strmax )) )
    for i,d in enumerate( strmax ):
      r = len(strmax) - i
      if i<len(strmax)-1:
         output += f"{ strmax[0:i+1] }[0-{ int(strmax[i+1])-(1 if r>2 else 0) }]"
         if r-2 > 0:
            output += f"[0-9]{{{ r-2 }}}"
         output += "|"
    output += f"[1-{int(strmax[0])-1}][0-9]{{{ len(strmax)-1 }}}|"
    output += f"[1-9][0-9]{{1,{len(strmax)-2}}}|"
    output += f"[{min}-9]"
    return output

def Test( min: int, max: int ):
  print( f"Test(min={min},max={max})" )
  regex = GenerateRegex(min,max)
  print( regex )
  pattern = re.compile( "^" + regex + "$" )
  for t in range(min,max if max<65536 else 65536):
      if not pattern.match( str(t) ):
          print( f"{t} does not match" )

Test( 0, 65535 )
Test( 1, 0xffffffff )

oc_route_distinguisher = ('^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|'
          + '6[0-4][0-9]{3}|[0-5][0-9]{4}|[1-9][0-9]{0,3}|0):'  # <= [0-5] => [1-5], 09999 is not a valid RD
          + '(429496729[0-5]|42949672[0-8][0-9]|'
          + '4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|'
          + '42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|'
          + '429[0-3][0-9]{6}|42[0-8][0-9]{7}|'
          + '4[0-1][0-9]{8}|3[0-9]{9}|[1-9][0-9]{0,8}|0)$') # <= 3[0-9] => [1-3][0-9], 2000000000 is a valid RD

oc_p = re.compile( oc_route_distinguisher )
print( f'09999:0 { oc_p.match("09999:0") }')
print( f'0:2000000000: { oc_p.match("0:2000000000") }')
