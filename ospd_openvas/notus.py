# -*- coding: utf-8 -*-
# Copyright (C) 2014-2021 Greenbone Networks GmbH
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from pathlib import Path
from typing import Dict, Optional
import json
import logging


logger = logging.getLogger(__name__)


class Notus:
    # caches the oids as well as the filepath to load the meta_data
    # probably better in redis
    cache: Dict[str, str]
    path: Path

    def __init__(self, path: str):
        self.path = Path(path)
        self.cache = {}

    def reload_cache(self):
        new_cache = {}
        for f in self.path.glob('*.notus'):
            filename = f.as_posix()
            data = json.loads(f.read_bytes())
            advisories = data.get("advisories", [])
            for advisory in advisories:
                new_cache[advisory["oid"]] = filename
        self.cache = new_cache

    def get_filenames_and_oids(self):
        if not self.cache:
            self.reload_cache()
        for k, v in self.cache.items():
            yield (Path(v).name, k)

    def find_advisory(self, path: Path, oid: str):
        advisories = json.loads(path.read_bytes())
        for advisory in advisories.get("advisories", []):
            if advisory.get("oid") == oid:
                return advisory

    def get_nvt_metadata(self, oid: str) -> Optional[Dict[str, str]]:
        if not self.cache:
            self.reload_cache()
        pstr = self.cache.get(oid)
        if not pstr:
            return None
        path = Path(pstr)
        advisory = self.find_advisory(path, oid)
        if not advisory:
            return None
        result = {}
        result["vt_params"] = []
        result["creation_time"] = str(advisory.get("creation_date", 0))
        result["last_modification"] = str(advisory.get("last_modification", 0))
        result["modification_time"] = str(advisory.get("last_modification", 0))
        result["summary"] = advisory.get("summary")
        result["impact"] = advisory.get("impact")
        result["affected"] = advisory.get("affected")
        result["insight"] = advisory.get("insight")
        # vuldetect and solution need to be clarrified
        # result['solution'] = None
        # result['vuldetect'] = None
        severity = {
            "CVSS:3": result.get("severity", {}).get("cvss_v3"),
            "CVSS:2": result.get("severity", {}).get("cvss_v2"),
            "severity_date": result.get("severity", {}).get("date"),
            "severity_origin": result.get("severity", {}).get("origin"),
        }
        result["severity_vector"] = severity

        result["filename"] = path.name
        result["required_keys"] = ""
        result["mandatory_keys"] = ""
        result["excluded_keys"] = ""
        result["required_udp_ports"] = ""
        result["required_ports"] = ""
        result["dependencies"] = ""
        result["tag"] = ""
        refs = {
            "bid": advisory.get("bid", []),
            "cve": advisory.get("cve", []),
            "xref": advisory.get("xrefs", []),
        }
        result["refs"] = refs
        result["category"] = advisory.get("category", "")
        result["family"] = path.stem
        result["name"] = advisory.get("title", "")
        return result
