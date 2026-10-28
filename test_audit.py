import pathlib
import shutil
import subprocess
import tempfile
import unittest

import audit


@unittest.skipUnless(
    all(shutil.which(tool) for tool in ("clang", "llvm-nm", "llvm-objdump", "strings")),
    "clang and LLVM binary tools are required",
)
class BinaryAuditTests(unittest.TestCase):
    def test_macho_symbols_are_detected_with_real_binary_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            image = root / "sample.o"
            subprocess.run(
                ["clang", "-target", "arm64-apple-macos13", "-x", "c", "-c", "-o", str(image), "-"],
                input=b"extern int external_value(void); int sample_value(void) { return external_value(); }\n",
                check=True,
                capture_output=True,
            )

            self.assertTrue(audit.is_macho(image))
            result = audit.image_audit(image, root)

            self.assertIn("_sample_value", result["private"]["defined_symbols"])
            self.assertIn("_external_value", result["private"]["undefined_symbols"])
            self.assertGreater(result["public"]["defined_symbol_count"], 0)
            self.assertEqual(result["public"]["undefined_symbol_count"], 1)
            self.assertEqual(result["public"]["tool_failure_count"], 0)
            self.assertEqual(result["private"]["tool_failures"], [])

    def test_invalid_image_retains_symbol_tool_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            image = root / "invalid.o"
            image.write_bytes(b"not an object file\n")

            result = audit.image_audit(image, root)

            self.assertEqual(result["public"]["defined_symbol_count"], 0)
            self.assertEqual(result["public"]["undefined_symbol_count"], 0)
            self.assertIn("defined_symbols_failed", result["private"]["tool_failures"])
            self.assertIn("undefined_symbols_failed", result["private"]["tool_failures"])
            self.assertGreaterEqual(result["public"]["tool_failure_count"], 2)


if __name__ == "__main__":
    unittest.main()
