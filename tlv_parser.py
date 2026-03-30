"""
BER-TLV Parser for SmartVista IIA/IMA files.

Custom length encoding:
  - Short form (byte < 0x80): length = byte, 2 hex chars
  - Long form (byte >= 0x80): length = ((byte & 0x7F) << 8) | next_byte, 4 hex chars

Tags are hex-encoded ASCII. Values are plain ASCII text.
Constructed tags (FF??, FF80??, FFFF??) contain nested TLVs.
Primitive tags (DF80??, DF??) contain raw values.
"""


def is_constructed(tag: str) -> bool:
    """Check if a tag is constructed (contains sub-TLVs)."""
    tag_upper = tag.upper()
    if tag_upper.startswith("FFFF"):
        return True
    if tag_upper.startswith("FF"):
        return True
    return False


def parse_tag(data: str, pos: int) -> tuple[str, int]:
    """Parse a TLV tag at position. Returns (tag, new_pos)."""
    if pos >= len(data):
        raise ParseError(pos, "Unexpected end of data while reading tag")

    # Read first byte (2 hex chars)
    if pos + 2 > len(data):
        raise ParseError(pos, f"Incomplete tag byte at position {pos}")

    byte1_hex = data[pos:pos + 2]
    try:
        byte1 = int(byte1_hex, 16)
    except ValueError:
        raise ParseError(pos, f"Invalid hex in tag: '{byte1_hex}'")

    # Check if low 5 bits are all 1s (= 0x1F) -> multi-byte tag
    if (byte1 & 0x1F) == 0x1F:
        # Read second byte
        if pos + 4 > len(data):
            raise ParseError(pos, f"Incomplete multi-byte tag at position {pos}")
        byte2_hex = data[pos + 2:pos + 4]
        try:
            byte2 = int(byte2_hex, 16)
        except ValueError:
            raise ParseError(pos + 2, f"Invalid hex in tag byte 2: '{byte2_hex}'")

        # Check if byte2 has continuation bit (bit 7)
        if byte2 & 0x80:
            # Three-byte tag
            if pos + 6 > len(data):
                raise ParseError(pos, f"Incomplete 3-byte tag at position {pos}")
            tag = data[pos:pos + 6].upper()
            return tag, pos + 6
        else:
            # Two-byte tag
            tag = data[pos:pos + 4].upper()
            return tag, pos + 4
    else:
        # Single-byte tag
        tag = data[pos:pos + 2].upper()
        return tag, pos + 2


def parse_length(data: str, pos: int) -> tuple[int, int]:
    """Parse custom length encoding. Returns (length, new_pos)."""
    if pos + 2 > len(data):
        raise ParseError(pos, "Unexpected end of data while reading length")

    byte1_hex = data[pos:pos + 2]
    try:
        byte1 = int(byte1_hex, 16)
    except ValueError:
        raise ParseError(pos, f"Invalid hex in length: '{byte1_hex}'")

    if byte1 < 0x80:
        # Short form
        return byte1, pos + 2
    else:
        # Long form: ((byte1 & 0x7F) << 8) | byte2
        if pos + 4 > len(data):
            raise ParseError(pos, f"Incomplete long-form length at position {pos}")
        byte2_hex = data[pos + 2:pos + 4]
        try:
            byte2 = int(byte2_hex, 16)
        except ValueError:
            raise ParseError(pos + 2, f"Invalid hex in length byte 2: '{byte2_hex}'")
        length = ((byte1 & 0x7F) << 8) | byte2
        return length, pos + 4


class ParseError(Exception):
    """TLV parsing error with position information."""
    def __init__(self, position: int, message: str, line: int = None):
        self.position = position
        self.line = line
        self.message = message
        super().__init__(f"Position {position}: {message}")


class TLVNode:
    """Represents a parsed TLV node."""
    def __init__(self, tag: str, value: str = "", children: list = None,
                 start_pos: int = 0, end_pos: int = 0, line: int = 0):
        self.tag = tag
        self.value = value
        self.children = children or []
        self.start_pos = start_pos
        self.end_pos = end_pos
        self.line = line

    def find_tag(self, tag: str) -> 'TLVNode | None':
        """Find first child with given tag."""
        for child in self.children:
            if child.tag == tag.upper():
                return child
        return None

    def find_all_tags(self, tag: str) -> list['TLVNode']:
        """Find all children with given tag."""
        return [c for c in self.children if c.tag == tag.upper()]

    def find_deep(self, tag: str) -> 'TLVNode | None':
        """Recursively find first node with given tag."""
        for child in self.children:
            if child.tag == tag.upper():
                return child
            result = child.find_deep(tag)
            if result:
                return result
        return None

    def get_value(self, tag: str) -> str | None:
        """Get value of first child with given tag."""
        node = self.find_tag(tag)
        return node.value if node else None

    def __repr__(self):
        if self.children:
            return f"TLVNode({self.tag}, children={len(self.children)})"
        return f"TLVNode({self.tag}, value='{self.value[:30]}')"


def parse_tlv(data: str, start: int = 0, end: int = None, line: int = 0,
              warnings: list = None, _data_len: int = None) -> list[TLVNode]:
    """Parse TLV data and return list of TLVNode objects."""
    if end is None:
        end = len(data)
    if warnings is None:
        warnings = []
    if _data_len is None:
        _data_len = len(data)

    nodes = []
    pos = start

    while pos < end:
        # Skip whitespace/newlines
        if data[pos] in (' ', '\t', '\r', '\n'):
            pos += 1
            continue

        node_start = pos

        # Parse tag and length
        tag, pos = parse_tag(data, pos)
        length, pos = parse_length(data, pos)

        # Check we have enough data — if parent block length is too short,
        # extend boundary and warn instead of failing
        if pos + length > end:
            if pos + length <= _data_len:
                overflow = (pos + length) - end
                warnings.append({
                    'line': line, 'position': node_start,
                    'message': f"Tag {tag} extends {overflow} chars beyond parent block boundary (block length mismatch)"
                })
                end = pos + length
            else:
                warnings.append({
                    'line': line, 'position': node_start,
                    'message': f"Tag {tag} declares length {length} but only {_data_len - pos} chars remain in file, skipping"
                })
                break

        if is_constructed(tag):
            children = parse_tlv(data, pos, pos + length, line=line,
                                 warnings=warnings, _data_len=_data_len)
            actual_end = pos + length
            if children:
                child_end = children[-1].end_pos
                if child_end > actual_end:
                    actual_end = child_end
            node = TLVNode(tag, "", children, node_start, actual_end, line)
            pos = actual_end
        else:
            value = data[pos:pos + length]
            node = TLVNode(tag, value, [], node_start, pos + length, line)
            pos = pos + length

        nodes.append(node)

    return nodes


def parse_iia_file(content: str) -> dict:
    """
    Parse a complete IIA/IMA file.
    Returns dict with 'header', 'records', 'trailer' as TLVNode lists,
    plus 'errors' for any parse issues.
    """
    lines = content.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    # Remove trailing empty lines
    while lines and not lines[-1].strip():
        lines.pop()

    result = {
        'header': None,
        'records': [],
        'trailer': None,
        'errors': [],
        'warnings': [],
        'lines': lines,
        'line_count': len(lines),
    }

    if len(lines) < 3:
        result['errors'].append({
            'line': 0, 'position': 0,
            'message': f"File must have at least 3 lines (header, data, trailer), found {len(lines)}"
        })
        return result

    # Parse header (line 1)
    try:
        warnings = []
        header_nodes = parse_tlv(lines[0], line=1, warnings=warnings)
        result['warnings'].extend(warnings)
        if header_nodes:
            result['header'] = header_nodes[0]
    except ParseError as e:
        result['errors'].append({
            'line': 1, 'position': e.position,
            'message': f"Header parse error: {e.message}"
        })

    # Parse data records (line 2 to second-to-last)
    for i in range(1, len(lines) - 1):
        line_data = lines[i].strip()
        if not line_data:
            continue
        try:
            warnings = []
            record_nodes = parse_tlv(line_data, line=i + 1, warnings=warnings)
            result['warnings'].extend(warnings)
            if record_nodes:
                result['records'].append(record_nodes[0])
        except ParseError as e:
            result['errors'].append({
                'line': i + 1, 'position': e.position,
                'message': f"Record parse error: {e.message}"
            })

    # Parse trailer (last line)
    last_line = lines[-1].strip()
    if last_line:
        try:
            warnings = []
            trailer_nodes = parse_tlv(last_line, line=len(lines), warnings=warnings)
            result['warnings'].extend(warnings)
            if trailer_nodes:
                result['trailer'] = trailer_nodes[0]
        except ParseError as e:
            result['errors'].append({
                'line': len(lines), 'position': e.position,
                'message': f"Trailer parse error: {e.message}"
            })

    return result
