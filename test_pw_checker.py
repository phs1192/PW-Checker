import math
import unittest

import pw_checker as pw

COMMON = {"password", "123456"}


class PoolAndEntropyTests(unittest.TestCase):
    def test_pool_size_per_character_class(self):
        self.assertEqual(pw.pool_size("abc"), 26)
        self.assertEqual(pw.pool_size("aB"), 52)
        self.assertEqual(pw.pool_size("aB3"), 62)
        self.assertEqual(pw.pool_size("aB3!"), 94)

    def test_entropy_formula(self):
        self.assertAlmostEqual(pw.entropy_bits("abcd"), 4 * math.log2(26))

    def test_empty_password_has_no_entropy(self):
        self.assertEqual(pw.entropy_bits(""), 0.0)


class PatternTests(unittest.TestCase):
    def test_repeats(self):
        self.assertTrue(pw.has_repeats("xaaay"))
        self.assertFalse(pw.has_repeats("aabbcc"))

    def test_sequences(self):
        self.assertTrue(pw.has_sequence("xx1234xx"))
        self.assertTrue(pw.has_sequence("ABCD"))
        self.assertTrue(pw.has_sequence("4321"))
        self.assertFalse(pw.has_sequence("k7#Pq"))


class AnalyzeTests(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        result = pw.analyze("Password", COMMON)
        self.assertTrue(result.is_common)
        self.assertEqual(result.rating, "very weak")

    def test_short_password_is_weak(self):
        self.assertIn(pw.analyze("aZ3!", COMMON).rating, ("very weak", "weak"))

    def test_long_random_password_is_very_strong(self):
        result = pw.analyze("t7#Kq!9vLz2$Wm8@Xp", COMMON)
        self.assertEqual(result.rating, "very strong")
        self.assertFalse(result.is_common)

    def test_tips_are_given_for_missing_classes(self):
        tips = " ".join(pw.analyze("abcdefghijkl", COMMON).tips)
        self.assertIn("uppercase", tips)
        self.assertIn("digits", tips)
        self.assertIn("symbols", tips)

    def test_pattern_penalty_lowers_entropy(self):
        plain = pw.entropy_bits("aaaK7#pQ")
        result = pw.analyze("aaaK7#pQ", COMMON)
        self.assertLess(result.entropy_bits, plain)


class CommonListTests(unittest.TestCase):
    def test_bundled_list_loads(self):
        common = pw.load_common_passwords()
        self.assertIn("123456", common)

    def test_missing_file_gives_empty_set(self):
        self.assertEqual(pw.load_common_passwords("does_not_exist.txt"), set())


if __name__ == "__main__":
    unittest.main()
