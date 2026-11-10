"""
MetaX GPS Extraction and Geolocation Processing Module.
Converts raw EXIF GPS tags into clean decimal coordinates, DMS strings,
and mapping service links.
"""

from typing import Optional, Dict, Any, Tuple, Union


def _parse_ratio(value: Any) -> float:
    """Safely converts a ratio, number, or rational string to float."""
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    
    # Handle exifread Ratio / Pillow IFD rational
    if hasattr(value, "num") and hasattr(value, "den"):
        return float(value.num) / float(value.den) if value.den != 0 else 0.0
    if isinstance(value, (tuple, list)) and len(value) == 2:
        return float(value[0]) / float(value[1]) if value[1] != 0 else 0.0

    # Handle string representations like "477970357/10000000" or "28"
    str_val = str(value).strip().strip("[]'\"")
    if "/" in str_val:
        parts = str_val.split("/")
        try:
            num = float(parts[0])
            den = float(parts[1])
            return num / den if den != 0 else 0.0
        except (ValueError, ZeroDivisionError):
            return 0.0
    try:
        return float(str_val)
    except ValueError:
        return 0.0


def _dms_to_decimal(degrees: float, minutes: float, seconds: float, ref: str) -> float:
    """Converts Degrees, Minutes, Seconds + Reference (N, S, E, W) to Decimal Degrees."""
    decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
    if ref and ref.upper() in ["S", "W"]:
        decimal = -decimal
    return round(decimal, 6)


def parse_dms_values(raw_coords: Any) -> Optional[Tuple[float, float, float]]:
    """Parses degrees, minutes, seconds from various EXIF formats."""
    if raw_coords is None:
        return None

    if isinstance(raw_coords, (list, tuple)) and len(raw_coords) == 3:
        d = _parse_ratio(raw_coords[0])
        m = _parse_ratio(raw_coords[1])
        s = _parse_ratio(raw_coords[2])
        return (d, m, s)

    text = str(raw_coords).strip()
    cleaned = text.strip("[]() ")
    if cleaned:
        tokens = [token.strip() for token in cleaned.split(",") if token.strip()]
        if len(tokens) == 3:
            d = _parse_ratio(tokens[0])
            m = _parse_ratio(tokens[1])
            s = _parse_ratio(tokens[2])
            return (d, m, s)

    return None


def format_dms(degrees: float, minutes: float, seconds: float, ref: str) -> str:
    """Formats coordinates into a clean human-readable DMS string."""
    return f"{int(degrees)}° {int(minutes)}' {seconds:.2f}\" {ref.upper()}"


def extract_gps_data(exif_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts and standardizes GPS data from an EXIF dictionary."""
    gps_info: Dict[str, Any] = {
        "has_gps": False,
        "latitude": None,
        "longitude": None,
        "latitude_dms": None,
        "longitude_dms": None,
        "formatted_coordinates": None,
        "altitude_meters": None,
        "maps_url": None,
        "osm_url": None,
        "raw": {}
    }

    normalized = {}
    for k, v in exif_dict.items():
        key_str = str(k).lower().replace(" ", "").replace("_", "")
        normalized[key_str] = v

    lat_val = (
        normalized.get("gpsgpslatitude") or
        normalized.get("gpslatitude") or
        normalized.get("latitude")
    )
    lat_ref = str(
        normalized.get("gpsgpslatituderef") or
        normalized.get("gpslatituderef") or
        normalized.get("latituderef") or
        "N"
    ).strip().upper()

    lon_val = (
        normalized.get("gpsgpslongitude") or
        normalized.get("gpslongitude") or
        normalized.get("longitude")
    )
    lon_ref = str(
        normalized.get("gpsgpslongituderef") or
        normalized.get("gpslongituderef") or
        normalized.get("longituderef") or
        "E"
    ).strip().upper()

    if lat_val and lon_val:
        lat_dms = parse_dms_values(lat_val)
        lon_dms = parse_dms_values(lon_val)

        if lat_dms and lon_dms:
            lat_dec = _dms_to_decimal(lat_dms[0], lat_dms[1], lat_dms[2], lat_ref)
            lon_dec = _dms_to_decimal(lon_dms[0], lon_dms[1], lon_dms[2], lon_ref)

            if -90 <= lat_dec <= 90 and -180 <= lon_dec <= 180 and not (lat_dec == 0 and lon_dec == 0):
                gps_info["has_gps"] = True
                gps_info["latitude"] = lat_dec
                gps_info["longitude"] = lon_dec
                gps_info["latitude_dms"] = format_dms(lat_dms[0], lat_dms[1], lat_dms[2], lat_ref)
                gps_info["longitude_dms"] = format_dms(lon_dms[0], lon_dms[1], lon_dms[2], lon_ref)
                gps_info["formatted_coordinates"] = f"{lat_dec:.6f}, {lon_dec:.6f}"
                gps_info["maps_url"] = f"https://www.google.com/maps?q={lat_dec},{lon_dec}"
                gps_info["osm_url"] = f"https://www.openstreetmap.org/?mlat={lat_dec}&mlon={lon_dec}#map=16/{lat_dec}/{lon_dec}"

    alt_val = normalized.get("gpsgpsaltitude") or normalized.get("gpsaltitude")
    alt_ref = normalized.get("gpsgpsaltituderef") or normalized.get("gpsaltituderef")
    if alt_val is not None:
        alt_meters = _parse_ratio(alt_val)
        if alt_ref and str(alt_ref).strip() in ["1", "b'\\x01'"]:
            alt_meters = -alt_meters
        gps_info["altitude_meters"] = round(alt_meters, 2)

    for tag in ["gpsdatestamp", "gpstimestamp", "gpsspeed", "gpsimgdirection"]:
        if tag in normalized:
            clean_tag = tag.replace("gps", "")
            gps_info["raw"][clean_tag] = str(normalized[tag])

    return gps_info

