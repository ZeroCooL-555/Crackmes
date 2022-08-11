#!/usr/bin/python

import angr

proj = angr.Project("revv")
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: b"Nice job! :)" in s.posix.dumps(1))
password = simgr.found[0].posix.dumps(0)
print(password.decode("utf-8"))
