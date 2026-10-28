import unittest

from hipaa_audit.assess.grounding import allowed_quantities, find_quantities, ungrounded_quantities


def keys(text: str) -> set[tuple[float, str]]:
    return {q.key for q in find_quantities(text)}


class FindQuantitiesTests(unittest.TestCase):
    def test_a_number_with_a_unit(self):
        self.assertEqual(keys("Sessions lock after 15 minutes of inactivity."), {(15, "minute")})
        self.assertEqual(keys("Passwords must be at least 12 characters long."), {(12, "character")})
        self.assertEqual(keys("Availability of 99.9% is expected."), {(99.9, "%")})
        self.assertEqual(keys("Availability of 99.9 percent is expected."), {(99.9, "%")})

    def test_numbers_written_in_words_and_with_brackets(self):
        self.assertEqual(keys("Kept for six years."), keys("Kept for 6 years."))
        self.assertEqual(keys("Within thirty (30) days of starting."), {(30, "day")})
        self.assertEqual(keys("Within twenty-four hours."), {(24, "hour")})

    def test_hyphenated_and_ranges(self):
        self.assertEqual(keys("A 30-day limit."), {(30, "day")})
        self.assertEqual(keys("Between 30 to 60 days."), {(30, "day"), (60, "day")})
        self.assertEqual(keys("Within 5 business days."), {(5, "day")})

    def test_years_are_twelve_months_and_weeks_are_seven_days(self):
        self.assertEqual(keys("Every year."), {(12, "month")})
        self.assertEqual(keys("Every 12 months."), {(12, "month")})
        self.assertEqual(keys("Once a year."), {(12, "month")})
        self.assertEqual(keys("Reviewed annually."), {(12, "month")})
        self.assertEqual(keys("Reviewed yearly."), {(12, "month")})
        self.assertEqual(keys("Reviewed quarterly."), {(3, "month")})
        self.assertEqual(keys("Reviewed every quarter."), {(3, "month")})
        self.assertEqual(keys("Every six months."), {(6, "month")})
        self.assertEqual(keys("Tested twice a year."), {(6, "month")})
        self.assertEqual(keys("Reviewed each week."), {(7, "day")})
        self.assertEqual(keys("Backed up nightly."), {(1, "day")})
        self.assertEqual(keys("Backed up every night."), {(1, "day")})

    def test_things_that_are_not_quantities(self):
        for text in (
            "Approved on 14 March 2026.",
            "Version 2.3 of the policy.",
            "Encrypted with AES-256 over TLS 1.2.",
            "See 45 CFR 164.312(a)(2)(i).",
            "Two of the three expected elements are addressed.",
            "The CISO and the Executive Committee.",
            "A policy that mentions it only in passing.",
        ):
            self.assertEqual(keys(text), set(), text)

    def test_the_text_that_was_matched_is_kept_for_display(self):
        self.assertEqual([q.shown for q in find_quantities("Locks after 15 minutes.")], ["15 minutes"])


class UngroundedQuantitiesTests(unittest.TestCase):
    ALLOWED = allowed_quantities(
        ["Sessions lock after 10 minutes of inactivity.", "Logs are kept for 12 months. Reviewed every quarter."]
    )

    def test_a_number_the_document_does_not_contain(self):
        self.assertEqual(ungrounded_quantities("Sessions lock after 15 minutes.", self.ALLOWED), ["15 minutes"])

    def test_a_number_the_document_contains(self):
        self.assertEqual(ungrounded_quantities("Sessions lock after ten minutes of inactivity.", self.ALLOWED), [])
        self.assertEqual(ungrounded_quantities("Logs are kept for one year and reviewed quarterly.", self.ALLOWED), [])

    def test_the_unit_matters(self):
        self.assertEqual(ungrounded_quantities("Sessions lock after 10 days.", self.ALLOWED), ["10 days"])

    def test_text_without_quantities_is_never_flagged(self):
        self.assertEqual(ungrounded_quantities("Two of the three elements are addressed.", self.ALLOWED), [])

    def test_each_offender_is_listed_once(self):
        text = "It locks after 15 minutes. Yes, 15 minutes and 20 minutes."
        self.assertEqual(ungrounded_quantities(text, self.ALLOWED), ["15 minutes", "20 minutes"])


if __name__ == "__main__":
    unittest.main()
