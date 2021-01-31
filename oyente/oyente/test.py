from z3 import *
import json

# data = {
# 'id' : 1,
# 'name' : 'test1',
# 'age' : '1'
# }
# data2 = [{
# 'id' : 1,
# 'name' : 'test1',
# 'age' : '1'
# },{
# 'id' : 2,
# 'name' : 'test2',
# 'age' : '2'
# }]
# json_str = json.dumps(data)
# json_str2=json.dumps(data2)
# data3 = json.loads(json_str)
# data4=json.loads(json_str2)
# print(json_str)
# print(json_str2)
# print (data3,data3['name'])
# print (data4)

# Not(If(ULE(50, Extract(159, 0, to)), 1, 0) != 0),                           -->50>to(0-159)
# If(And(Extract(159, 7, to) == 0,ULE(Extract(6, 0, to), 100)),1,0) !=0       -->t0(0-6)!=0,to(0-6)<=100
#
# 50<=to(0-159)
# And(Extract(159, 7, to) == 0,ULE(Extract(6, 0, to), 100) )=1
#
# and(to(7-159),to(0-6)<=100 )=1
#
# to(0-6)<=100
a = BitVec('a',6)
b = BitVec('b',6)

s = Solver()
s.add(a>b)
c=1
# while s.check() == sat:
#   print s.model()
#   s.add(b != s.model()[b]) # prevent next model from using the same assignment as a previous model
while s.check() == sat:
  if(s.model()[c]>8):
    print c
    print s.model()[c]
    print s.model()
