#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def bubble_sort(arr):
    size = len(arr)
    for i in range(size - 1):
        for j in range(size - i - 1):
            if arr[j] > arr[j + 1]:
                arr[j], arr[j + 1] = arr[j + 1], arr[j]

    return arr

if __name__ == "__main__":
    arr = [-1, -3, 0, 1, 3, -3, -5, 2]

    print(f"Unsorted array: {arr}")
    bubble_sort(arr)
    print(f"Sorted array: {arr}")
