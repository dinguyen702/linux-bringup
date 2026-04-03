"""
Python String Principles and Manipulation Test
9th Grade Computer Science
Total Points: 23
"""

# ============================================================
# SECTION 1: Multiple Choice (1 point each, 5 points total)
# ============================================================
# Circle the letter of the best answer.
#
# 1. (1 pt) What does the following expression return?
#       len("Hello, World!")
#    a) 12
#    b) 13
#    c) 11
#    d) 14
#
# 2. (1 pt) Which of the following correctly creates a string in Python?
#    a) my_str = Hello
#    b) my_str = 'Hello'
#    c) my_str = (Hello)
#    d) my_str = [Hello]
#
# 3. (1 pt) What is the index of the character 'W' in "Hello, World!"?
#    a) 6
#    b) 8
#    c) 7
#    d) 9
#
# 4. (1 pt) What does the string method .upper() do?
#    a) Removes all spaces from a string
#    b) Converts all characters in a string to uppercase
#    c) Converts all characters in a string to lowercase
#    d) Reverses the string
#
# 5. (1 pt) What is the output of the following code?
#       word = "python"
#       print(word[0] + word[-1])
#    a) "pn"
#    b) "py"
#    c) "on"
#    d) "po"
#
# Answer Key: 1-b, 2-b, 3-c, 4-b, 5-a


# ============================================================
# SECTION 2: Fill in the Blank (1 point each, 5 points total)
# ============================================================
# Complete each statement with the correct answer.
#
# 6. (1 pt) String indices in Python start at __________.
#
# 7. (1 pt) The operator used to concatenate (join) two strings is __________.
#
# 8. (1 pt) To access the last character of a string without knowing its
#           length, you can use the index __________.
#
# 9. (1 pt) The string method __________ removes leading and trailing
#           whitespace from a string.
#
# 10. (1 pt) A string that cannot be changed after it is created is called
#            __________.
#
# Answer Key: 6-0, 7-+, 8--1, 9-.strip(), 10-immutable


# ============================================================
# SECTION 3: Short Answer (2 points each, 6 points total)
# ============================================================
# Answer each question in 1–2 sentences or with a short code example.
#
# 11. (2 pts) Explain what string slicing is and give one example using the
#             string "programming".
#
#    _________________________________________________________________
#    _________________________________________________________________
#    Example: ________________________________________________________
#
#
# 12. (2 pts) What is the difference between the .find() method and the
#             .index() method when the target substring is NOT found in
#             the string?
#
#    _________________________________________________________________
#    _________________________________________________________________
#
#
# 13. (2 pts) Write Python code that takes the string "Hello, World!" and
#             prints it in all lowercase letters.
#
#    _________________________________________________________________
#    _________________________________________________________________
#
# Answer Key:
#   11. Slicing extracts a portion of a string using [start:stop:step] syntax.
#       e.g., "programming"[0:7] → "program"
#   12. .find() returns -1 when the substring is not found;
#       .index() raises a ValueError.
#   13. print("Hello, World!".lower())


# ============================================================
# SECTION 4: Coding Questions (variable points, 7 points total)
# ============================================================
# Write Python code that satisfies each prompt.
# Comments in your code will earn partial credit.
#
# 14. (3 pts) Write a function called reverse_string that accepts one string
#             parameter and returns the string reversed.
#             Example: reverse_string("hello") should return "olleh"
#
#    def reverse_string(s):
#        _____________________________________________________________
#        _____________________________________________________________
#        _____________________________________________________________
#
#
# 15. (4 pts) Write a function called count_vowels that accepts one string
#             parameter and returns the number of vowels (a, e, i, o, u —
#             both uppercase and lowercase) in that string.
#             Example: count_vowels("Hello World") should return 3
#
#    def count_vowels(s):
#        _____________________________________________________________
#        _____________________________________________________________
#        _____________________________________________________________
#        _____________________________________________________________
#        _____________________________________________________________
#
# Answer Key:
#   14.
#       def reverse_string(s):
#           return s[::-1]
#
#   15.
#       def count_vowels(s):
#           count = 0
#           for ch in s:
#               if ch.lower() in "aeiou":
#                   count += 1
#           return count


# ============================================================
# BONUS (optional, +2 extra credit points)
# ============================================================
# 16. (+2 EC) Write a function called is_palindrome that accepts a string
#             and returns True if the string is a palindrome (reads the same
#             forwards and backwards, ignoring spaces and capitalization),
#             and False otherwise.
#             Example: is_palindrome("Race car") should return True
#
#    def is_palindrome(s):
#        _____________________________________________________________
#        _____________________________________________________________
#        _____________________________________________________________
#
# Answer Key:
#       def is_palindrome(s):
#           cleaned = s.replace(" ", "").lower()
#           return cleaned == cleaned[::-1]


# ============================================================
# ANSWER KEY — Reference implementations for grading
# ============================================================

def reverse_string(s):
    """Returns the reverse of string s. (Q14 — 3 pts)"""
    return s[::-1]


def count_vowels(s):
    """Returns the count of vowels in string s. (Q15 — 4 pts)"""
    count = 0
    for ch in s:
        if ch.lower() in "aeiou":
            count += 1
    return count


def is_palindrome(s):
    """Returns True if s is a palindrome, ignoring spaces and case. (Bonus — 2 EC pts)"""
    cleaned = s.replace(" ", "").lower()
    return cleaned == cleaned[::-1]


# ============================================================
# Quick self-check — run this file to verify the answer key
# ============================================================
if __name__ == "__main__":
    # Section 1 spot checks
    assert len("Hello, World!") == 13, "Q1 answer should be 13"
    assert "Hello, World!"[7] == "W",  "Q3 answer: index of 'W' is 7"
    word = "python"
    assert word[0] + word[-1] == "pn",  "Q5 answer is 'pn'"

    # Section 3 spot checks
    assert "Hello, World!".lower() == "hello, world!", "Q13 answer"
    assert "programming"[0:7] == "program",            "Q11 slicing example"

    # Section 4 function checks
    assert reverse_string("hello") == "olleh",         "Q14: reverse_string"
    assert count_vowels("Hello World") == 3,           "Q15: count_vowels"

    # Bonus check
    assert is_palindrome("Race car") is True,          "Bonus: palindrome"
    assert is_palindrome("hello") is False,            "Bonus: not palindrome"

    print("All answer-key checks passed!")
    print()
    print("=== GRADING SUMMARY ===")
    print("Section 1 — Multiple Choice : 5 pts  (1 pt each)")
    print("Section 2 — Fill in Blank   : 5 pts  (1 pt each)")
    print("Section 3 — Short Answer    : 6 pts  (2 pts each)")
    print("Section 4 — Coding          : 7 pts  (Q14: 3 pts | Q15: 4 pts)")
    print("-----------------------------------------------")
    print("Total                       : 23 pts")
    print("Bonus (optional)            : +2 EC pts")
