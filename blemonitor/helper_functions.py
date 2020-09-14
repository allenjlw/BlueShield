#!/usr/bin/python
import numpy as np

def isAligned(pkt1, pkt2, pkt3, interval):
    result = set()
    if abs(pkt1.time - pkt2.time)/1000 > interval:
        # 1 and 2 do not belong to the same adv event
        if pkt1.time < pkt2.time:
            result.add(1)
        else:
            result.add(2)
    if abs(pkt1.time - pkt3.time)/1000 > interval:
        # 1 and 3 do not belong to the same adv event
        if pkt1.time < pkt3.time:
            result.add(1)
        else:
            result.add(3)
    if abs(pkt2.time - pkt3.time)/1000 > interval:
        # 2 and 3 do not belong to the same adv event
        if pkt2.time < pkt3.time:
            result.add(2)
        elif not 3 in result:
            result.add(3)
    return sorted(result)
