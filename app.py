import streamlit as st
import os
from tlv_parser import parse_iia_file, TLVNode
from validator import validate_file, get_tag_name, BTRT_TAG_MAP

st.set_page_config(page_title="IIA File Checker", page_icon="🔍", layout="wide")

st.title("IIA File Format Checker")
st.caption("SmartVista BER-TLV Application Processing Interface validator")

# --- File input ---
uploaded_files = st.file_uploader(
    "Upload IIA files",
    type=None,
    accept_multiple_files=True,
    help="Upload one or more SmartVista application processing interface files to validate"
)

sample_dir = os.path.join(os.path.dirname(__file__), "iia_sample")
sample_files = []
if os.path.isdir(sample_dir):
    sample_files = sorted(os.listdir(sample_dir))

use_sample = st.checkbox("Or pick from sample files", value=False)
selected_samples = []
if use_sample and sample_files:
    selected_samples = st.multiselect("Sample files", sample_files)

# --- Build file list: (filename, content) ---
files = []

for uf in uploaded_files:
    raw = uf.read()
    try:
        content = raw.decode('utf-8')
    except UnicodeDecodeError:
        content = raw.decode('latin-1')
    files.append((uf.name, content))

for sname in selected_samples:
    filepath = os.path.join(sample_dir, sname)
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        files.append((sname, f.read()))

if not files:
    st.stop()

# --- Validate all files ---
st.divider()
results = []
for filename, content in files:
    result = validate_file(content)
    results.append((filename, content, result))

# --- Summary table ---
total = len(results)
valid_count = sum(1 for _, _, r in results if r.is_valid)
error_count = total - valid_count
warn_count = sum(1 for _, _, r in results if r.warnings)

st.subheader(f"Results: {total} file(s)")

col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Total Files", total)
with col2:
    if valid_count == total:
        st.metric("Passed", f"{valid_count}/{total}", delta="All OK", delta_color="normal")
    else:
        st.metric("Passed", f"{valid_count}/{total}")
with col3:
    if error_count > 0:
        st.metric("Failed", error_count, delta=f"{error_count} with errors", delta_color="inverse")
    else:
        st.metric("Failed", 0)

# Summary row per file
for filename, content, result in results:
    btrt_types = result.stats.get('btrt_types', [])
    btrt_str = ", ".join(c for c, d in btrt_types) if btrt_types else "—"
    ftype = result.stats.get('file_type', '?')
    inst = result.stats.get('institution', '?')
    size = result.stats.get('file_size', len(content))

    if result.is_valid and not result.warnings:
        icon = "✅"
    elif result.is_valid:
        icon = "⚠️"
    else:
        icon = "❌"

    label = f"{icon} `{filename}` — **{btrt_str}** | {ftype} | Inst: {inst} | {size:,} bytes"
    if not result.is_valid:
        label += f" | **{len(result.errors)} error(s)**"
    if result.warnings:
        label += f" | {len(result.warnings)} warning(s)"

    with st.expander(label, expanded=(not result.is_valid)):
        # Stats row
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("File Size", f"{size:,} bytes")
        with c2:
            st.metric("Lines", result.stats.get('line_count', '?'))
        with c3:
            st.metric("Records", result.stats.get('record_count', '?'))
        with c4:
            st.metric("File Type", ftype)

        # BTRT types
        for code, desc in btrt_types:
            st.info(f"**{code}** — {desc}")

        # File details
        details = {
            "Institution": inst,
            "Agent Code": result.stats.get('agent_code', '—'),
            "File Date": result.stats.get('file_date', '—'),
            "Declared Records": result.stats.get('declared_records', '—'),
            "CRC": result.stats.get('crc', '—'),
        }
        cols = st.columns(len(details))
        for i, (k, v) in enumerate(details.items()):
            with cols[i]:
                st.metric(k, v)

        # Errors
        if result.errors:
            st.markdown("**Errors**")
            for err in result.errors:
                loc_parts = []
                if err.line:
                    loc_parts.append(f"Line {err.line}")
                if err.position is not None:
                    loc_parts.append(f"Col {err.position}")
                if err.tag:
                    loc_parts.append(f"Tag `{err.tag}` ({get_tag_name(err.tag)})")
                loc = " | ".join(loc_parts)
                st.markdown(f"❌ **{loc}**: {err.message}")

        # Warnings
        if result.warnings:
            st.markdown("**Warnings**")
            for warn in result.warnings:
                loc_parts = []
                if warn.line:
                    loc_parts.append(f"Line {warn.line}")
                if warn.position is not None:
                    loc_parts.append(f"Col {warn.position}")
                if warn.tag:
                    loc_parts.append(f"Tag `{warn.tag}` ({get_tag_name(warn.tag)})")
                loc = " | ".join(loc_parts)
                st.markdown(f"⚠️ **{loc}**: {warn.message}")

        # TLV Tree
        with st.expander("TLV Structure Tree"):
            parsed = parse_iia_file(content)

            def render_tree(node: TLVNode, depth: int = 0, _key_prefix: str = ""):
                name = get_tag_name(node.tag)
                if node.children:
                    with st.expander(
                        f"{'　' * depth}📁 `{node.tag}` — {name} ({len(node.children)} children)",
                        expanded=(depth < 1)
                    ):
                        for j, child in enumerate(node.children):
                            render_tree(child, depth + 1, _key_prefix=f"{_key_prefix}_{j}")
                else:
                    val = node.value if len(node.value) <= 80 else node.value[:77] + "..."
                    st.markdown(f"{'　' * depth}📄 `{node.tag}` **{name}** = `{val}`")

            if parsed['header']:
                st.markdown("**Header (Line 1)**")
                render_tree(parsed['header'], _key_prefix=f"{filename}_h")
            for ri, record in enumerate(parsed['records']):
                tag = record.tag.upper()
                btrt_info = BTRT_TAG_MAP.get(tag, ('?', 'Unknown'))
                st.markdown(f"**Record {ri+1} (Line {record.line}) — {btrt_info[0]}**")
                render_tree(record, _key_prefix=f"{filename}_r{ri}")
            if parsed['trailer']:
                st.markdown(f"**Trailer (Line {parsed['trailer'].line})**")
                render_tree(parsed['trailer'], _key_prefix=f"{filename}_t")

        # Raw content
        with st.expander("Raw File Content"):
            lines = content.replace('\r\n', '\n').split('\n')
            for li, line in enumerate(lines):
                if line.strip():
                    st.code(f"Line {li+1}: {line[:200]}{'...' if len(line) > 200 else ''}", language=None)
