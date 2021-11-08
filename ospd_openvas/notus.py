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
from typing import Any, Dict, Iterator, Optional
import json
import logging


from redis import Redis

logger = logging.getLogger(__name__)


class Cache:
    def __init__(self, db: Redis, prefix: str = "internal/notus/advisories"):
        self.db = db
        self.__prefix = prefix

    def store_advisory(self, oid: str, value: Dict[str, str]):
        return self.db.lpush(f"{self.__prefix}/{oid}", json.dumps(value))

    def exists(self, oid: str) -> bool:
        return self.db.exists(f"{self.__prefix}/{oid}") == 1

    def get_advisory(self, oid: str) -> Optional[Dict[str, str]]:
        result = self.db.lindex(f"{self.__prefix}/{oid}", 0)
        if result:
            return json.loads(result)
        return None

    def get_keys(self) -> Iterator[str]:
        for key in self.db.scan_iter(f"{self.__prefix}*"):
            yield str(key).split('/')[-1]


class Notus:
    # caches the oids as well as the filepath to load the meta_data
    # probably better in redis
    cache: Cache
    loaded: bool = False
    path: Path

    def __init__(self, path: str, redis: Redis):
        self.path = Path(path)
        self.cache = Cache(redis)

    def reload_cache(self):
        for f in self.path.glob('*.notus'):
            data = json.loads(f.read_bytes())
            advisories = data.get("advisories", [])
            for advisory in advisories:
                res = self.__to_ospd(f, advisory)
                self.cache.store_advisory(advisory["oid"], res)
        self.loaded = True

    def __to_ospd(self, path: Path, advisory: Dict[str, Any]):
        result = {}
        result["vt_params"] = []
        result["creation_date"] = str(advisory.get("creation_date", 0))
        result["last_modification"] = str(advisory.get("last_modification", 0))
        result["modification_time"] = str(advisory.get("last_modification", 0))
        result["summary"] = advisory.get("summary")
        result["impact"] = advisory.get("impact")
        result["affected"] = advisory.get("affected")
        result["insight"] = advisory.get("insight")
        result['solution'] = "Please install the updated package(s)."
        result['solution_type'] = "VendorFix"
        result[
            'vuldetect'
        ] = 'Checks if a vulnerable package version is present on the target host.'
        result['qod_type'] = 'package'
        severity = advisory.get('severity', {})
        result["severity_vector"] = severity.get(
            "cvss_v3", severity.get("cvss_v2", "")
        )

        result["filename"] = path.name
        bid = advisory.get("bid", [])
        cve = advisory.get("cve", [])
        xref = advisory.get("xrefs", [])
        refs = {}
        if bid:
            refs['bid'] = bid
        if cve:
            refs['cve'] = cve
        if xref:
            refs['xref'] = xref

        result["refs"] = refs
        result["family"] = path.stem
        result["name"] = advisory.get("title", "")
        return result

    def get_filenames_and_oids(self):
        if not self.loaded:
            self.reload_cache()
        for key in self.cache.get_keys():
            adv = self.cache.get_advisory(key)
            if adv:
                yield (adv.get("filename", ""), key)

    def exists(self, oid: str) -> bool:
        return self.cache.exists(oid)

    def get_nvt_metadata(self, oid: str) -> Optional[Dict[str, str]]:
        return self.cache.get_advisory(oid)
