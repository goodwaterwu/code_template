#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def binary_search(arr, low, high, key):
    while low <= high:
        middle = low + (high - low) // 2;

        if arr[middle] == key:
            return middle;

        if arr[middle] < key:
            low = middle + 1;
        else:
            high = middle - 1;

    return -1

if __name__ == "__main__":
    arr = [-5, -4, -3, -2, -1, 0, 1, 2, 3]
    key = int(input("Find key: "))

    print("-" * 50)
    print(f"Array: {arr}")
    print(f"Key: {key}")
    print("-" * 50)
    ret = binary_search(arr, 0, len(arr) - 1, key)
    if ret >= 0:
        print(f"Found {key} on the index of the array: {ret}");
    else:
        print(f"Couldn't find {key} in the array");
