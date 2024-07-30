#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def linear_search(values, key):
    for i in range(len(values)):
        if values[i] == key:
            return i

    return -1

if __name__ == "__main__":
    values = [-1, -3, 0, 3, 1, -2, -4, -5, 2]
    key = int(input("Find key: "))

    print("-" * 50)
    print(f"Array: {values}")
    print(f"Key: {key}")
    print("-" * 50)
    ret = linear_search(values, key)
    if ret >= 0:
        print(f"Found {key} on the index of the array: {ret}");
    else:
        print(f"Couldn't find {key} in the array");
