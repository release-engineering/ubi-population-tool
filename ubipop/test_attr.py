import attr
import inspect


@attr.s
class Coordinates(object):
    x = attr.ib()


print(inspect.getsource(Coordinates.__init__))
##xxx = XXX(100, 200)#
# print(xxx.x)
