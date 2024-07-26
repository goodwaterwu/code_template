#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def merge(arr, l, m, r):
    n1 = m - l + 1
    n2 = r - m
    left = arr[l:m+1]
    right = arr[m+1:r+1]
    i = 0
    j = 0
    k = l

    while i < n1 and j < n2:
        if left[i] < right[j]:
            arr[k] = left[i]
            i += 1
        else:
            arr[k] = right[j]
            j += 1
        k += 1

    while i < n1:
        arr[k] = left[i]
        i += 1
        k += 1

    while j < n2:
        arr[k] = right[j]
        j += 1
        k += 1

    return arr

def merge_sort(arr, l, r):
    if r > l:
        m = l + (r - l) // 2
        merge_sort(arr, l, m)
        merge_sort(arr, m + 1, r)
        merge(arr, l, m, r)

    return arr

if __name__ == "__main__":
    arr = [-1, -3, 0, 1, 3, -3, -5, 2]

    print(f"Unsorted array: {arr}")
    merge_sort(arr, 0, len(arr) - 1)
    print(f"Sorted array: {arr}")
