#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def partition(arr, low, high):
    index = low
    for i in range(low, high + 1):
        if arr[i] < arr[high]:
            arr[index], arr[i] = arr[i], arr[index]
            index += 1
    arr[index], arr[high] = arr[high], arr[index]

    return index

def quick_sort(arr, low, high):
    if low < high:
        index = partition(arr, low, high)
        quick_sort(arr, 0, index - 1)
        quick_sort(arr, index + 1, high)

    return arr

if __name__ == "__main__":
    arr = [-1, -3, 0, 1, 3, -3, -5, 2]

    print(f"Unsorted array: {arr}")
    quick_sort(arr, 0, len(arr) - 1)
    print(f"Sorted array: {arr}")
