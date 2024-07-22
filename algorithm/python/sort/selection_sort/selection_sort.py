#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def selection_sort(arr):
    size = len(arr)
    for i in range(size - 1):
        min_index = i
        for j in range(i + 1, size):
            if arr[j] < arr[min_index]:
                min_index = j
        arr[i], arr[min_index] = arr[min_index], arr[i]

    return arr

if __name__ == "__main__":
    arr = [-1, -3, 0, 1, 3, -3, -5, 2]

    print(f"Unsorted array: {arr}")
    selection_sort(arr)
    print(f"Sorted array: {arr}")
