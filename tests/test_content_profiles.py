"""S5CF-T02/T03 hostile parser coverage for the synthetic Chat-first content profiles."""

from __future__ import annotations

from io import BytesIO
import unittest
import warnings
from zipfile import ZIP_DEFLATED, ZipFile

from tests.chat_fixtures import minimal_docx, synthetic_text
from vault_next.content_profiles import ContentProfileError, ContentProfileRouter


class ContentProfileTests(unittest.TestCase):
    """All parser input is disposable invented bytes created in memory by each test."""

    def setUp(self) -> None:
        self.router = ContentProfileRouter()

    def test_s5cf_t02_automatic_format_routing_rejects_declaration_spoofing(self) -> None:
        plain = self.router.route(
            synthetic_text(),
            declared_media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            declared_extension=".docx",
        )
        markdown = self.router.route(
            b"VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\n\n# Invented\n\nFixture paragraph.\n",
            declared_media_type="text/markdown",
            declared_extension=".txt",
        )
        docx = self.router.route(
            minimal_docx(),
            declared_media_type="text/plain",
            declared_extension=".txt",
        )
        self.assertEqual(plain.profile_id, "plain_text")
        self.assertEqual(markdown.profile_id, "markdown_text")
        self.assertEqual(docx.profile_id, "docx_wordprocessingml")
        self.assertTrue(docx.anchors[0].anchor.startswith("paragraph:"))

    def test_owner_selected_anchor_budget_can_extend_default_without_changing_it(self) -> None:
        material = "\n".join(f"# Section {index}\nEvidence {index}" for index in range(257)).encode()
        with self.assertRaises(ContentProfileError):
            self.router.route(material, declared_media_type="text/markdown", declared_extension=".md")
        normalized = ContentProfileRouter(max_anchors=1024).route(
            material, declared_media_type="text/markdown", declared_extension=".md"
        )
        self.assertEqual(len(normalized.anchors), 514)

    def test_s5cf_t03_hostile_docx_containers_fail_closed_without_fallback(self) -> None:
        external_relationship = (
            b'<?xml version="1.0"?><Relationships '
            b'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship Id="rId1" Target="https://example.invalid" TargetMode="External"/>'
            b"</Relationships>"
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            duplicate = minimal_docx(extras=[("word/document.xml", b"duplicate")])
        hostile = [
            minimal_docx(extras=[("word/vbaProject.bin", b"fixture")]),
            minimal_docx(extras=[("word/embeddings/object.bin", b"fixture")]),
            minimal_docx(extras=[("word/_rels/document.xml.rels", external_relationship)]),
            minimal_docx(extras=[("../outside", b"fixture")]),
            duplicate,
            b"PK\x03\x04not-a-valid-zip",
        ]
        constrained = ContentProfileRouter(max_zip_total_uncompressed=64)
        hostile.append(minimal_docx())
        for material in hostile:
            router = constrained if material == hostile[-1] else self.router
            with self.subTest(size=len(material)):
                with self.assertRaises(ContentProfileError):
                    router.route(
                        material,
                        declared_media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        declared_extension=".docx",
                    )
        with self.assertRaises(ContentProfileError):
            self.router.route(
                self._malformed_document_xml(),
                declared_media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                declared_extension=".docx",
            )

    @staticmethod
    def _malformed_document_xml() -> bytes:
        output = BytesIO()
        with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
            archive.writestr(
                "[Content_Types].xml",
                b'<Types><Override ContentType="wordprocessingml.document.main+xml"/></Types>',
            )
            archive.writestr("word/document.xml", b"<w:document>")
        return output.getvalue()
