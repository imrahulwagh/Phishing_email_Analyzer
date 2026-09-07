import os
import io
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from pathlib import Path
from PIL import Image
import imagehash
from ingestion.eml_parser import ParsedEmail, ParsedImage


BRAND_DOMAINS = {
    "paypal": ["paypal.com", "paypal.co.uk"],
    "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "aws.amazon.com"]
}


@dataclass
class BrandMatch:
    brand_name: str
    reference_logo_path: str
    hamming_distance: int
    matched_image_filename: str
    legitimate_domains: List[str]
    domain_authorized: bool


@dataclass
class ImageAnalysisResult:
    total_images_extracted: int
    brand_matches: List[BrandMatch] = field(default_factory=list)
    has_unauthorized_logo_impersonation: bool = False
    risk_score: float = 0.0
    flags: List[str] = field(default_factory=list)


class LogoDetector:
    def __init__(self, reference_dir: Optional[str] = None, max_hamming_distance: int = 12):
        if reference_dir is None:
            reference_dir = Path(__file__).parent / "reference_logos"
        self.reference_dir = Path(reference_dir)
        self.max_hamming_distance = max_hamming_distance
        self.reference_hashes: Dict[str, Dict[str, Any]] = {}
        self._load_reference_logos()

    def _load_reference_logos(self):
        """Loads and pre-computes perceptual hashes for all reference brand logos in reference_dir."""
        if not self.reference_dir.exists():
            self.reference_dir.mkdir(parents=True, exist_ok=True)
            return

        valid_extensions = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}
        for file in self.reference_dir.iterdir():
            if file.suffix.lower() in valid_extensions:
                try:
                    with Image.open(file) as img:
                        img_converted = img.convert("RGB")
                        phash = imagehash.phash(img_converted)
                        dhash = imagehash.dhash(img_converted)
                        brand_key = file.stem.lower().split("_")[0]
                        self.reference_hashes[file.name] = {
                            "brand": brand_key,
                            "file_path": str(file),
                            "phash": phash,
                            "dhash": dhash,
                            "domains": BRAND_DOMAINS.get(brand_key, [f"{brand_key}.com"])
                        }
                except Exception as e:
                    pass

    def analyze(self, email_data: ParsedEmail) -> ImageAnalysisResult:
        if not email_data.images or not self.reference_hashes:
            return ImageAnalysisResult(
                total_images_extracted=len(email_data.images),
                brand_matches=[],
                has_unauthorized_logo_impersonation=False,
                risk_score=0.0,
                flags=[]
            )

        matches: List[BrandMatch] = []
        flags: List[str] = []
        unauthorized_impersonation = False
        sender_domain = email_data.sender_domain.lower()

        for parsed_img in email_data.images:
            try:
                img_io = io.BytesIO(parsed_img.data)
                with Image.open(img_io) as img:
                    img_rgb = img.convert("RGB")
                    img_phash = imagehash.phash(img_rgb)
                    img_dhash = imagehash.dhash(img_rgb)

                    for ref_name, ref_info in self.reference_hashes.items():
                        dist_p = int(img_phash - ref_info["phash"])
                        dist_d = int(img_dhash - ref_info["dhash"])
                        min_dist = min(dist_p, dist_d)

                        if min_dist <= self.max_hamming_distance:
                            legit_domains = ref_info["domains"]
                            is_authorized = any(sender_domain.endswith(d) for d in legit_domains) if sender_domain else False

                            match_entry = BrandMatch(
                                brand_name=ref_info["brand"],
                                reference_logo_path=ref_info["file_path"],
                                hamming_distance=int(min_dist),
                                matched_image_filename=parsed_img.filename,
                                legitimate_domains=legit_domains,
                                domain_authorized=is_authorized
                            )
                            matches.append(match_entry)

                            if not is_authorized:
                                unauthorized_impersonation = True
                                flags.append(
                                    f"Detected impersonated '{ref_info['brand']}' logo in email from unauthorized domain '{sender_domain}' (Hamming Dist: {min_dist})"
                                )
            except Exception:
                continue

        matches.sort(key=lambda m: m.hamming_distance)

        risk = 0.0
        if unauthorized_impersonation:
            risk = 0.85
        elif matches:
            risk = 0.10  # Authorized brand logo present in legit email

        return ImageAnalysisResult(
            total_images_extracted=len(email_data.images),
            brand_matches=matches,
            has_unauthorized_logo_impersonation=unauthorized_impersonation,
            risk_score=risk,
            flags=flags
        )
