#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def bubble_sort(arr):
    size = len(arr)
    for i in range(1, size):
        key_index = i
        for j in range(i - 1, -1, -1):
            if arr[key_index] < arr[j]:
                arr[key_index], arr[j] = arr[j], arr[key_index]
                key_index = j

    return arr

if __name__ == "__main__":
    arr = [-1, -3, 0, 1, 3, -3, -5, 2]

    print(f"Unsorted array: {arr}")
    bubble_sort(arr)
    print(f"Sorted array: {arr}")
