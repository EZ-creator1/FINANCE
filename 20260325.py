class chain(object):
    def __init__(self,path=""):
        self._path = path
    def __getattr__(self, item):
        return chain("%s/%s" % (self._path, item))
    def __str__(self):        return self._path
    __repr__ = __str__
print(chain().status.user.timeline.list)
class student(object):
    def __init__(self,name):
        self.name = name
    def __call__(self):
        print("My name is %s." % self.name)
s = student("Luyi")
s()

from enum import Enum, unique

class Gender(Enum):
    Male = 0
    Female = 1

class Student(object):
    def __init__(self, name, gender):
        self.name = name
        self.gender = gender

# 测试:
bart = Student('Bart', Gender.Male)
if bart.gender == Gender.Male:
    print('测试通过!')
else:
    print('测试失败!')

from functools import reduce

def str2num(s):
    return float(s)

def calc(exp):
    ss = exp.split('+')
    ns = map(str2num, ss)
    return reduce(lambda acc, x: acc + x, ns)

def main():
    r = calc('100 + 200 + 345')
    print('100 + 200 + 345 =', r)
    r = calc('99 + 88 + 7.6')
    print('99 + 88 + 7.6 =', r)

main()

