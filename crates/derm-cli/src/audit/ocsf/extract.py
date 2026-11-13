"""Extracts, from the OCSF schema repository at v1.9.0 (commit 856d462),
the part of the schema `derm audit export --ocsf` writes into: the six
classes it maps to, the profile it names, and every object reachable from
their attributes, resolved through `extends` and `$include`. The output is
`ocsf-1.9.0-subset.json` beside this file; `audit::ocsf`'s tests validate
every event the mapping makes against it. Run:

    git clone --depth 1 --branch v1.9.0 https://github.com/ocsf/ocsf-schema s
    python3 extract.py s > ocsf-1.9.0-subset.json

Only this repository's JSON files are read; nothing else runs.
"""
import json, os, sys, glob

root = sys.argv[1]
J = lambda p: json.load(open(os.path.join(root, p)))
dic = J("dictionary.json")["attributes"]
events = {}
for f in glob.glob(os.path.join(root, "events/**/*.json"), recursive=True):
    d = json.load(open(f))
    events[d["name"]] = d
objects = {}
for f in glob.glob(os.path.join(root, "objects/*.json")):
    d = json.load(open(f))
    objects[d["name"]] = d
cats = J("categories.json")["attributes"]

def merged_attrs(chain):
    out = {}
    profiles = {}
    for d in reversed(chain):
        for inc in d.get("attributes", {}).get("$include", []) or []:
            p = J(inc)
            for k, v in p.get("attributes", {}).items():
                if k == "$include":
                    continue
                out.setdefault(k, {}).update(v)
                out[k]["profile"] = p.get("name")
        for k, v in d.get("attributes", {}).items():
            if k == "$include":
                continue
            prof = out.get(k, {}).get("profile")
            enum = dict(out.get(k, {}).get("enum", {}))
            out.setdefault(k, {}).update(v)
            if enum and "enum" in v:
                enum.update(v["enum"])
                out[k]["enum"] = enum
            if prof and "requirement" not in v:
                out[k]["profile"] = prof
            elif "profile" in out[k] and k in d.get("attributes", {}):
                out[k].pop("profile", None)
    return out

def describe(attrs):
    res = {}
    for k, v in attrs.items():
        base = dic.get(k, {})
        t = v.get("type") or base.get("type")
        # A class's or object's enum extends the dictionary's (its 0 Unknown
        # and 99 Other): both are valid values.
        enum = dict(base.get("enum") or {})
        enum.update(v.get("enum") or {})
        item = {"requirement": v.get("requirement", "optional"), "type": t,
                "array": bool(v.get("is_array", base.get("is_array", False)))}
        if enum:
            item["enum"] = {e: x.get("caption") for e, x in enum.items()}
        if v.get("profile"):
            item["profile"] = v["profile"]
        res[k] = item
    return res

def ev_chain(name):
    c = [events[name]]
    while c[-1].get("extends"):
        c.append(events[c[-1]["extends"]])
    return c

def obj_chain(name):
    c = [objects[name]]
    while c[-1].get("extends") and c[-1]["extends"] in objects:
        c.append(objects[c[-1]["extends"]])
    return c

out = {"version": J("version.json")["version"], "commit": "856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba",
       "classes": {}, "objects": {}, "categories": {v["uid"]: v["caption"] for v in cats.values()}}
# Category 0 is the base event's own (its `category_uid` enum).
out["categories"][0] = J("events/base_event.json")["attributes"]["category_uid"]["enum"]["0"]["caption"]
want = ["base_event", "process_activity", "file_activity", "network_activity", "api_activity", "detection_finding"]
todo = []
for n in want:
    c = ev_chain(n)
    cat = next((d.get("category") for d in c if d.get("category")), None)
    cat_uid = cats[cat]["uid"] if cat in cats else 0
    uid = c[0].get("uid")
    class_uid = 0 if uid is None else cat_uid * 1000 + uid
    a = describe(merged_attrs(c))
    # A class's own uids are derived (category uid * 1000 + class uid), so
    # its `class_uid` and `category_uid` enums hold its own values only.
    a["class_uid"]["enum"] = {str(class_uid): c[0].get("caption")}
    a["category_uid"]["enum"] = {str(cat_uid): cats[cat]["caption"] if cat in cats else "Uncategorized"}
    out["classes"][str(class_uid)] = {"name": n, "caption": c[0].get("caption"), "category_uid": cat_uid, "attributes": a}
    todo += [x["type"] for x in a.values()]
seen = set()
while todo:
    t = todo.pop()
    if t is None or t.endswith("_t") or t in seen or t not in objects:
        continue
    seen.add(t)
    c = obj_chain(t)
    a = describe(merged_attrs(c))
    cons = {}
    for d in c:
        for k, v in (d.get("constraints") or {}).items():
            cons.setdefault(k, v)
    out["objects"][t] = {"attributes": a, "constraints": cons}
    todo += [x["type"] for x in a.values()]
json.dump(out, sys.stdout, indent=0, sort_keys=True)
print()
