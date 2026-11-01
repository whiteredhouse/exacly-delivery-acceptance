"""Deterministic business examples; no credentials, provider calls or effects."""

import unittest

from canary_app import total_cents


class InvoiceTotalTests(unittest.TestCase):
    def test_empty_invoice_has_no_amount_due(self):
        self.assertEqual(total_cents([]), 0)

    def test_mixed_invoice_matches_the_hand_calculated_total(self):
        # Two $1.25 items plus one $3.99 item = $6.49.
        self.assertEqual(total_cents([(125, 2), (399, 1)]), 649)

    def test_free_items_do_not_change_the_amount_due(self):
        self.assertEqual(total_cents([(0, 50), (199, 3)]), 597)

    def test_large_invoice_keeps_exact_integer_cents(self):
        self.assertEqual(total_cents([(10**18 + 1, 3), (2, 7)]), 3_000_000_000_000_000_017)

    def test_line_items_can_be_consumed_once(self):
        items = ((price, quantity) for price, quantity in [(250, 2), (75, 4)])
        self.assertEqual(total_cents(items), 800)

    def test_invalid_prices_are_rejected(self):
        for price in [-1, 1.5, "125", True, None]:
            with self.subTest(price=price), self.assertRaises(ValueError):
                total_cents([(price, 1)])

    def test_invalid_quantities_are_rejected(self):
        for quantity in [-1, 0, 1.5, "2", True, None]:
            with self.subTest(quantity=quantity), self.assertRaises(ValueError):
                total_cents([(125, quantity)])


if __name__ == "__main__":
    unittest.main()
