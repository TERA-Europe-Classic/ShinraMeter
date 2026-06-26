#!/usr/bin/env python3
"""Sync Shinra combat lookup data from an Elinu DataCenter checkout.

This intentionally targets the files Shinra loads at runtime for skill and NPC
lookups. It keeps Shinra's legacy per-hit metadata where possible, while using
Elinu as the source of truth for current IDs, localized names, icons, HP, boss
flags, and species IDs.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import re
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from xml.sax.saxutils import escape


LOCALES = {
    "EU-EN": "DataCenter_Final_EUR",
    "EU-FR": "DataCenter_Final_FRA",
    "EU-GER": "DataCenter_Final_GER",
    "RU": "DataCenter_Final_RUS",
}

CLASS_ORDER = [
    "Archer",
    "Berserker",
    "Brawler",
    "Common",
    "Gunner",
    "Lancer",
    "Mystic",
    "Ninja",
    "Priest",
    "Reaper",
    "Slayer",
    "Sorcerer",
    "Valkyrie",
    "Warrior",
]

ELINU_TO_SHINRA_CLASS = {
    "Assassin": "Ninja",
    "Elementalist": "Mystic",
    "Engineer": "Gunner",
    "Fighter": "Brawler",
    "Glaiver": "Valkyrie",
    "Soulless": "Reaper",
}

INVALID_XML_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


@dataclass(frozen=True)
class SkillKey:
    skill_id: int
    race: str
    gender: str
    player_class: str


@dataclass
class SkillRow:
    key: SkillKey
    name: str
    chained: str = "False"
    detail: str = ""
    icon: str = ""


@dataclass
class MonsterTemplate:
    template_id: int
    name: str
    hp: int
    is_boss: bool
    species_id: int


def iter_xml_files(directory: Path) -> Iterable[Path]:
    return sorted(p for p in directory.glob("*.xml") if not p.name.lower().endswith(".xsd"))


def root_without_namespace(path: Path) -> ET.Element:
    root = ET.parse(path).getroot()
    for elem in root.iter():
        if "}" in elem.tag:
            elem.tag = elem.tag.rsplit("}", 1)[1]
    return root


def parse_bool(value: str | None) -> bool:
    return str(value or "").lower() == "true"


def parse_int(value: str | None, default: int = 0) -> int:
    if value in (None, ""):
        return default
    try:
        return int(float(value))
    except ValueError:
        return default


def normalize_icon(icon: str | None) -> str:
    return (icon or "").strip().lower()


def normalize_player_class(player_class: str | None) -> str:
    value = player_class or "Common"
    return ELINU_TO_SHINRA_CLASS.get(value, value)


def clean_text(value: str | None) -> str:
    return INVALID_XML_CHARS.sub("", value or "")


def escape_attr(value: str) -> str:
    return escape(value, {'"': "&quot;"})


def read_baseline_text(path: Path, repo: Path, baseline_ref: str | None, relative_path: Path) -> str | None:
    if baseline_ref:
        try:
            return subprocess.check_output(
                ["git", "-C", str(repo / "resources" / "data"), "show", f"{baseline_ref}:{relative_path.as_posix()}"],
                text=True,
                encoding="utf-8-sig",
                errors="replace",
            )
        except subprocess.CalledProcessError:
            pass
    if path.exists():
        return path.read_text(encoding="utf-8-sig", errors="replace")
    return None


def read_existing_skills(path: Path, repo: Path, baseline_ref: str | None, relative_path: Path) -> dict[SkillKey, SkillRow]:
    rows: dict[SkillKey, SkillRow] = {}
    text = read_baseline_text(path, repo, baseline_ref, relative_path)
    if text is None:
        return rows
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        key = SkillKey(parse_int(parts[0]), parts[1], parts[2], parts[3])
        rows[key] = SkillRow(key, parts[4], parts[5], parts[6], parts[7])
    return rows


def read_override_runtime_keys(repo: Path, baseline_ref: str | None, locale: str) -> set[tuple[int, str, str, str]]:
    relative_path = Path("skills") / f"skills-override-{locale}.tsv"
    path = repo / "resources" / "data" / relative_path
    text = read_baseline_text(path, repo, baseline_ref, relative_path)
    keys: set[tuple[int, str, str, str]] = set()
    if text is None:
        return keys
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        keys.add((parse_int(parts[0]), parts[1], parts[2], parts[3]))
    return keys


def load_skill_icons(client_dc: Path) -> dict[SkillKey, str]:
    icons: dict[SkillKey, str] = {}
    for path in iter_xml_files(client_dc / "SkillIconData"):
        for elem in root_without_namespace(path).iter("Icon"):
            key = SkillKey(
                parse_int(elem.get("skillId")),
                elem.get("race", "Common"),
                elem.get("gender", "Common"),
                normalize_player_class(elem.get("class", "Common")),
            )
            icons[key] = normalize_icon(elem.get("iconName"))
    return icons


def base_skill_icon(skill_id: int, icons: dict[SkillKey, str], race: str, gender: str, cls: str) -> str:
    candidates = [
        SkillKey(skill_id, race, gender, cls),
        SkillKey(skill_id, "Common", "Common", cls),
        SkillKey(skill_id, "Common", "Common", "Common"),
    ]
    # Per-hit damage IDs frequently append a hit digit; use the base tooltip icon.
    if skill_id > 10:
        base10 = skill_id - (skill_id % 10)
        candidates.extend(
            [
                SkillKey(base10, race, gender, cls),
                SkillKey(base10, "Common", "Common", cls),
                SkillKey(base10, "Common", "Common", "Common"),
            ]
        )
    for key in candidates:
        icon = icons.get(key)
        if icon:
            return icon
    return ""


def generate_skills(
    locale: str,
    client_dc: Path,
    repo: Path,
    baseline_ref: str | None,
    existing_path: Path,
    relative_path: Path,
    output_path: Path,
) -> int:
    existing = read_existing_skills(existing_path, repo, baseline_ref, relative_path)
    override_runtime_keys = read_override_runtime_keys(repo, baseline_ref, locale)
    icons = load_skill_icons(client_dc)
    rows: dict[SkillKey, SkillRow] = {key: SkillRow(value.key, value.name, value.chained, value.detail, value.icon) for key, value in existing.items()}

    for path in iter_xml_files(client_dc / "StrSheet_UserSkill"):
        for elem in root_without_namespace(path).iter("String"):
            name = clean_text(elem.get("name", ""))
            if not name:
                continue
            key = SkillKey(
                parse_int(elem.get("id")),
                elem.get("race", "Common"),
                elem.get("gender", "Common"),
                normalize_player_class(elem.get("class", "Common")),
            )
            old = existing.get(key)
            if old is None and (key.skill_id, key.race, key.gender, key.player_class) in override_runtime_keys:
                continue
            icon = base_skill_icon(key.skill_id, icons, key.race, key.gender, key.player_class)
            row_icon = icon or (old.icon if old else "") or "icon_skills.voidtrap_tex"
            rows[key] = SkillRow(
                key=key,
                name=name,
                chained=old.chained if old else "False",
                detail=old.detail if old else "",
                icon=row_icon,
            )

    def sort_key(row: SkillRow) -> tuple[int, int, str, str, str]:
        try:
            class_index = CLASS_ORDER.index(row.key.player_class)
        except ValueError:
            class_index = len(CLASS_ORDER)
        return (class_index, row.key.skill_id, row.key.race, row.key.gender, row.key.player_class)

    lines = [
        "\t".join(
            [
                str(row.key.skill_id),
                row.key.race,
                row.key.gender,
                row.key.player_class,
                row.name,
                row.chained,
                row.detail,
                row.icon,
            ]
        )
        for row in sorted(rows.values(), key=sort_key)
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def zone_names_from_existing(path: Path, repo: Path, baseline_ref: str | None, relative_path: Path) -> dict[int, str]:
    text = read_baseline_text(path, repo, baseline_ref, relative_path)
    if text is None:
        return {}
    names: dict[int, str] = {}
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return names
    for zone in root.findall("Zone"):
        names[parse_int(zone.get("id"))] = zone.get("name", "unknown")
    return names


def load_zone_names(client_dc: Path) -> dict[int, str]:
    names: dict[int, str] = {}
    # Prefer the direct zone-name sheet, then broader region/dungeon labels for
    # Classic+ event and instance zones that are absent from StrSheet_ZoneName.
    for sheet in ["StrSheet_ZoneName", "StrSheet_Region", "StrSheet_Dungeon"]:
        directory = client_dc / sheet
        if not directory.exists():
            continue
        for path in iter_xml_files(directory):
            root = root_without_namespace(path)
            for elem in root.findall("String"):
                zone_id = parse_int(elem.get("id"))
                name = clean_text(elem.get("string", "")).strip()
                if zone_id and name:
                    names.setdefault(zone_id, name)
    return names


def load_creature_names(client_dc: Path) -> tuple[dict[int, dict[int, str]], dict[int, str]]:
    names: dict[int, dict[int, str]] = {}
    for path in iter_xml_files(client_dc / "StrSheet_Creature"):
        root = root_without_namespace(path)
        for hz in root.findall("HuntingZone"):
            zone_id = parse_int(hz.get("id"))
            names.setdefault(zone_id, {})
            for elem in hz.findall("String"):
                template_id = parse_int(elem.get("templateId"))
                name = clean_text(elem.get("name", ""))
                if name:
                    names[zone_id][template_id] = name
    return names, {}


def load_npc_templates(elinu_root: Path, creature_names: dict[int, dict[int, str]]) -> dict[int, dict[int, MonsterTemplate]]:
    templates: dict[int, dict[int, MonsterTemplate]] = {}
    npc_dir = elinu_root / "Server" / "Datasheet" / "NpcData"
    for path in sorted(npc_dir.glob("NpcData_*.xml")):
        root = root_without_namespace(path)
        zone_id = parse_int(root.get("huntingZoneId") or re.search(r"NpcData_(\d+)\.xml$", path.name).group(1))
        zone_templates = templates.setdefault(zone_id, {})
        for elem in root.findall("Template"):
            template_id = parse_int(elem.get("id"))
            stat = elem.find("Stat")
            hp = parse_int(stat.get("maxHp") if stat is not None else None)
            name = clean_text(creature_names.get(zone_id, {}).get(template_id) or elem.get("name") or f"Npc {zone_id} {template_id}")
            is_boss = parse_bool(elem.get("elite")) or elem.get("huntingStyle", "").lower() == "raid"
            species_id = parse_int(elem.get("speciesId"))
            zone_templates[template_id] = MonsterTemplate(template_id, name, hp, is_boss, species_id)
    return templates


def generate_monsters(
    locale: str,
    client_dc: Path,
    elinu_root: Path,
    repo: Path,
    baseline_ref: str | None,
    existing_path: Path,
    relative_path: Path,
    output_path: Path,
) -> int:
    creature_names, _ = load_creature_names(client_dc)
    source_zone_names = load_zone_names(client_dc)
    if locale != "EU-EN":
        english_zone_names = load_zone_names(elinu_root / "Client" / LOCALES["EU-EN"])
        for zone_id, name in english_zone_names.items():
            source_zone_names.setdefault(zone_id, name)
    existing_zone_names = zone_names_from_existing(existing_path, repo, baseline_ref, relative_path)
    templates = load_npc_templates(elinu_root, creature_names)

    lines = ['<?xml version="1.0" encoding="utf-8"?>', "<Zones>"]
    count = 0
    for zone_id in sorted(set(creature_names) | set(templates)):
        existing_zone_name = existing_zone_names.get(zone_id, "")
        if existing_zone_name.lower() == "unknown":
            existing_zone_name = ""
        zone_name = source_zone_names.get(zone_id) or existing_zone_name or f"Zone {zone_id}"
        lines.append(f'\t<Zone id="{zone_id}" name="{escape_attr(zone_name)}" >')
        zone_templates = templates.get(zone_id, {})
        for template_id in sorted(set(creature_names.get(zone_id, {})) | set(zone_templates)):
            template = zone_templates.get(template_id)
            if template is None:
                template = MonsterTemplate(
                    template_id,
                    creature_names.get(zone_id, {}).get(template_id, f"Npc {zone_id} {template_id}"),
                    0,
                    False,
                    0,
                )
            boss = "True" if template.is_boss else "False"
            lines.append(
                f'\t\t<Monster name="{escape_attr(template.name)}" id="{template.template_id}" '
                f'isBoss="{boss}" hp="{template.hp}" speciesId="{template.species_id}" />'
            )
            count += 1
        lines.append("\t</Zone>")
    lines.append("</Zones>")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return count


def copy_runtime_files(resources_data: Path, packaged_data: Path, locales: Iterable[str]) -> None:
    for locale in locales:
        for subdir, name in [
            ("skills", f"skills-{locale}.tsv"),
            ("monsters", f"monsters-{locale}.xml"),
        ]:
            src = resources_data / subdir / name
            dst = packaged_data / subdir / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--elinu", type=Path, required=True)
    parser.add_argument("--baseline-ref", help="Optional git ref in resources/data used as the merge baseline.")
    parser.add_argument("--locales", nargs="*", default=list(LOCALES))
    args = parser.parse_args()

    repo = args.repo.resolve()
    elinu = args.elinu.resolve()
    resources_data = repo / "resources" / "data"
    packaged_data = repo / "DamageMeter.UI" / "Resources" / "data"
    manifest: dict[str, dict[str, int]] = {}

    for locale in args.locales:
        dc_name = LOCALES[locale]
        client_dc = elinu / "Client" / dc_name
        if not client_dc.exists():
            raise FileNotFoundError(client_dc)
        skill_path = resources_data / "skills" / f"skills-{locale}.tsv"
        monster_path = resources_data / "monsters" / f"monsters-{locale}.xml"
        skill_relative_path = Path("skills") / f"skills-{locale}.tsv"
        monster_relative_path = Path("monsters") / f"monsters-{locale}.xml"
        manifest[locale] = {
            "skills": generate_skills(locale, client_dc, repo, args.baseline_ref, skill_path, skill_relative_path, skill_path),
            "monsters": generate_monsters(locale, client_dc, elinu, repo, args.baseline_ref, monster_path, monster_relative_path, monster_path),
        }

    copy_runtime_files(resources_data, packaged_data, args.locales)
    manifest_path = repo / "tools" / "sync_elinu_dc_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
