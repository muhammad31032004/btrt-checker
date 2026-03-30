"""
IIA/IMA file format validator against SmartVista BTRT specification.
"""

from tlv_parser import TLVNode, parse_iia_file

# ============================================================================
# BTRT type definitions: tag -> (btrt_code, description)
# ============================================================================
BTRT_TAG_MAP = {
    'FFFF01': ('BTRT01', 'New Card+Account for New Individual Customer'),
    'FFFF02': ('BTRT02', 'Card+Account for New Cardholder, Existing Customer'),
    'FFFF03': ('BTRT03', 'New Supplementary Card, Existing Customer'),
    'FFFF04': ('BTRT04', 'New Supplementary Account, Existing Customer'),
    'FFFF05': ('BTRT05', 'New Corporate Customer'),
    'FFFF06': ('BTRT06', 'Card+Account for Corporate Cardholder'),
    'FFFF07': ('BTRT07', 'New Account for Corporate Customer'),
    'FFFF08': ('BTRT08', 'New Card for Corporate Customer'),
    'FFFF09': ('BTRT10', 'Instant Issuing Pool Card'),
    'FFFF17': ('BTRT15', 'Card/Account Status Change'),
    'FFFF49': ('BTRT18', 'Change Merchant-Cardholder Contract Status'),
    'FFFF34': ('BTRT19', 'Unipago Distributor-Retailer Contract'),
    'FFFF0A': ('BTRT20', 'Card Renewal/Replacement'),
    'FFFF0B': ('BTRT21', 'Customer Migration'),
    'FFFF0C': ('BTRT25', 'Issuer Contract Change'),
    'FFFF0D': ('BTRT30', 'Issuer Data Change'),
    'FFFF0E': ('BTRT35', 'Issuer Additional Services'),
    'FFFF16': ('BTRT40', 'Issuer Structure Migration'),
    'FFFF0F': ('BTRT51/55', 'Merchant Registration + Account / Full Merchant Tree'),
    'FFFF10': ('BTRT52', 'Terminal Registration'),
    'FFFF11': ('BTRT53', 'Merchant Sub-level Registration'),
    'FFFF12': ('BTRT54', 'Merchant Account Application'),
    'FFFF35': ('BTRT56', 'Merchant Data Change'),
    'FFFF41': ('BTRT59', 'Bind Acquirer Services'),
    'FFFF13': ('BTRT60', 'Merchant Contract Change'),
}

# ============================================================================
# Expected block structure per BTRT type
# Key = BTRT tag, Value = dict of block_tag -> 'M'/'O'
# ============================================================================
BTRT_BLOCKS = {
    'FFFF01': {'FF2E': 'M', 'FF20': 'O', 'FF2C': 'M', 'FF24': 'M', 'FF26': 'M', 'FF2F': 'O', 'FF3C': 'O'},
    'FFFF02': {'FF2E': 'M', 'FF20': 'M', 'FF2C': 'M', 'FF24': 'M', 'FF26': 'M', 'FF2F': 'O', 'FF3C': 'O'},
    'FFFF03': {'FF2E': 'M', 'FF20': 'M', 'FF2C': 'M', 'FF24': 'M', 'FF26': 'M', 'FF2F': 'O', 'FF3C': 'O'},
    'FFFF04': {'FF2E': 'M', 'FF20': 'M', 'FF2C': 'M', 'FF24': 'M', 'FF26': 'M', 'FF3C': 'O'},
    'FFFF05': {'FF2E': 'M', 'FF20': 'M', 'FF8002': 'M', 'FF26': 'M', 'FF3C': 'O'},
    'FFFF06': {'FF2E': 'M', 'FF20': 'M', 'FF2C': 'M', 'FF24': 'M', 'FF26': 'M', 'FF2F': 'O', 'FF3C': 'O'},
    'FFFF07': {'FF2E': 'M', 'FF20': 'M', 'FF26': 'M', 'FF3C': 'O'},
    'FFFF08': {'FF2E': 'M', 'FF20': 'M', 'FF2C': 'M', 'FF24': 'M', 'FF26': 'M', 'FF2F': 'O', 'FF3C': 'O'},
    'FFFF09': {'FF2E': 'M', 'FF20': 'M', 'FF2C': 'M', 'FF24': 'M', 'FF26': 'M', 'FF3C': 'O'},
    'FFFF17': {'FF2E': 'M', 'FF20': 'M', 'FF8020': 'O', 'FF8021': 'O', 'FF805F': 'O', 'FF806F': 'O', 'FF3C': 'O'},
    'FFFF49': {'FF2E': 'M', 'FF806B': 'M', 'FF8055': 'O', 'FF8056': 'O', 'FF3C': 'O'},
    'FFFF34': {'FF2E': 'M', 'FF806B': 'M', 'FF8055': 'M', 'FF8056': 'M', 'FF3C': 'O'},
    'FFFF0A': {'FF2E': 'M', 'FF20': 'M', 'FF2C': 'M', 'FF24': 'M', 'FF26': 'O', 'FF2F': 'O', 'FF3C': 'O'},
    'FFFF0B': {'FF2E': 'M', 'FF20': 'M', 'FF2C': 'O', 'FF24': 'O', 'FF26': 'O', 'FF3C': 'O'},
    'FFFF0C': {'FF2E': 'M', 'FF20': 'M', 'FF2C': 'O', 'FF24': 'O', 'FF26': 'O', 'FF3C': 'O'},
    'FFFF0D': {'FF2E': 'M', 'FF20': 'O', 'FF8002': 'O', 'FF3C': 'O'},
    'FFFF0E': {'FF2E': 'M', 'FF20': 'M', 'FF2C': 'O', 'FF24': 'O', 'FF26': 'O', 'FF2F': 'M', 'FF3C': 'O'},
    'FFFF16': {'FF2E': 'M', 'FF20': 'M', 'FF2C': 'O', 'FF24': 'O', 'FF26': 'O', 'FF2F': 'O', 'FF3C': 'O'},
    'FFFF0F': {'FF2E': 'M', 'FF8003': 'M', 'FF26': 'O', 'FF3C': 'O'},
    'FFFF10': {'FF2E': 'M', 'FF8003': 'M', 'FF8006': 'M', 'FF3C': 'O'},
    'FFFF11': {'FF2E': 'M', 'FF8003': 'M', 'FF26': 'O', 'FF3C': 'O'},
    'FFFF12': {'FF2E': 'M', 'FF8003': 'M', 'FF26': 'M', 'FF3C': 'O'},
    'FFFF35': {'FF2E': 'M', 'FF8003': 'M', 'FF8002': 'O', 'FF3C': 'O'},
    'FFFF41': {'FF2E': 'M', 'FF2F': 'M', 'FF3C': 'O'},
    'FFFF13': {'FF2E': 'M', 'FF8003': 'M', 'FF26': 'O', 'FF3C': 'O'},
}

# ============================================================================
# Mandatory tags within key blocks
# ============================================================================
MAIN_BLOCK_MANDATORY = {'DF8000', 'DF8002', 'DF803F'}  # App Type, Contract ID, Officer ID

HEADER_MANDATORY = {'DF807D', 'DF807C', 'DF8079', 'DF807A'}  # File Type, Date, Institution, Agent

# Block-level mandatory tag sets (tag -> set of mandatory DF tags)
BLOCK_MANDATORY_TAGS = {
    'FF2E': {'DF8000', 'DF803F'},  # MAIN: App Type + Officer
    'FF22': {'DF8007'},  # PERSON: Person ID (conditional but usually required)
    'FF33': set(),  # CARD_INIT
    'FF36': {'DF8033', 'DF8035', 'DF8034'},  # ACCOUNT_INIT: number, type, currency
}

# Tag name lookup for display
TAG_NAMES = {
    # Header/Trailer
    'FF45': 'File Header', 'FF49': 'Header Block', 'FF46': 'File Trailer', 'FF4A': 'Trailer Block',
    'DF805D': 'Sequence Number', 'DF807D': 'File Type', 'DF807C': 'File Date',
    'DF8079': 'Institution Number', 'DF807A': 'Agent Code',
    'DF807E': 'Record Count', 'DF8060': 'CRC',
    # Main block
    'FF2E': 'MAIN_BLOCK', 'DF8041': 'Application ID', 'DF8000': 'Application Type',
    'DF8001': 'Record Number', 'DF8002': 'Contract ID', 'DF803F': 'Officer ID',
    'DF803A': 'Primary Flag', 'DF803D': 'Reject Code', 'DF803E': 'Application Source',
    # Customer block
    'FF20': 'CUSTOMER_BLOCK', 'DF8003': 'Customer ID', 'DF8006': 'VIP Code',
    'DF8004': 'Customer Description', 'DF8418': 'INN', 'DF8419': 'KPP',
    # Person/Identity
    'FF2C': 'CUSTOMER_IDENTIFICATION_BLOCK', 'FF22': 'PERSON_BLOCK', 'FF2A': 'ADDRESS_BLOCK',
    'DF8007': 'Person ID', 'DF8019': 'First Name', 'DF801A': 'Second Name',
    'DF801B': 'Surname', 'DF801C': 'Date of Birth', 'DF8108': 'Processing Mode',
    'DF800F': 'Company Name', 'DF8008': 'Sex', 'DF800A': 'Residence',
    'DF800D': 'Position', 'DF803B': 'ID Type', 'DF803C': 'ID Number',
    'DF8261': 'ID Series', 'DF8344': 'ID Authority', 'DF8345': 'ID Issue Date',
    'DF8346': 'ID Expire Date', 'DF8826': 'ID Number 2',
    # Address
    'DF801D': 'Address ID', 'DF801E': 'Address Type', 'DF8020': 'Address Line 1',
    'DF8021': 'Address Line 2', 'DF801F': 'Box/House', 'DF8024': 'Region',
    'DF8025': 'Country', 'DF8026': 'Postal Code', 'DF8029': 'Mobile Phone',
    'DF802B': 'Email',
    # Card
    'FF24': 'CARD_BLOCK', 'FF33': 'CARD_INIT_BLOCK', 'FF34': 'CARD_DATA_BLOCK',
    'DF802C': 'Card Number', 'DF802F': 'Card Type', 'DF8042': 'Embossed Name',
    'DF8030': 'Default ATM Account', 'DF8031': 'Default POS Account',
    'DF802E': 'Card Status', 'DF8175': 'Hot Card Status',
    'DF8670': 'Embossed Name National', 'DF8048': 'Express Flag',
    'DF8078': 'Card Expiration Date', 'DF817B': 'PIN Mode',
    # Account
    'FF26': 'ACCOUNT_BLOCK', 'FF36': 'ACCOUNT_INIT_BLOCK', 'FF37': 'ACCOUNT_DATA_BLOCK',
    'DF8033': 'Account Number', 'DF8035': 'Account Type', 'DF8034': 'Currency Code',
    'DF8036': 'Account Status',
    # Additional service
    'FF2F': 'ADDITIONAL_SERVICE_BLOCK',
    # Contact info
    'FF8002': 'CONTACT_INFORMATION_BLOCK',
    # Merchant
    'FF8003': 'MERCHANT_BLOCK', 'FF8005': 'TERMINAL_BLOCK', 'FF8006': 'TERMINAL_REGISTRATION_BLOCK',
    # Status change
    'FF8020': 'CARD_STATUS_CHANGE_BLOCK', 'FF8021': 'ACCT_STATUS_CHANGE_BLOCK',
    'FF805F': 'GROUP_CARD_STATUS_CHANGE_BLOCK', 'FF806F': 'PLASTIC_STATUS_CHANGE_BLOCK',
    # Reference
    'FF3C': 'REFERENCE_BLOCK', 'DF8061': 'Link Account with Card',
    # Registration
    'FF4C': 'REG_RECORD_BLOCK', 'DF805B': 'Service Type', 'DF805C': 'Service Level',
    'DF804A': 'Reg Start Date', 'DF812D': 'Service Ref',
    # Service/misc
    'FF8018': 'PHONE_BLOCK', 'FF806B': 'UNIPAGO_DETAILS_BLOCK',
    'FF8055': 'RETAILER_BLOCK', 'FF8056': 'DISTRIBUTOR_BLOCK',
    'FF8054': 'ADDITIONAL_PARAMETERS_BLOCK', 'FF804B': 'PARAMETER_BLOCK',
    'DF802D': 'Card Primary', 'DF8013': 'Security ID',
    'DF8050': 'Card Re-Link Flag', 'DF804F': 'Bank Card Flag',
    'DF8047': 'Delivery Agent Code', 'DF8521': 'Statement Scheme',
}


def get_tag_name(tag: str) -> str:
    return TAG_NAMES.get(tag.upper(), tag)


class ValidationError:
    def __init__(self, level: str, message: str, line: int = None,
                 position: int = None, tag: str = None, block: str = None):
        self.level = level  # 'error' or 'warning'
        self.message = message
        self.line = line
        self.position = position
        self.tag = tag
        self.block = block

    def __repr__(self):
        loc = ""
        if self.line:
            loc += f"Line {self.line}"
        if self.position is not None:
            loc += f" Col {self.position}"
        if self.tag:
            loc += f" [{self.tag}]"
        prefix = "ERROR" if self.level == 'error' else "WARN"
        return f"{prefix} {loc}: {self.message}"


class ValidationResult:
    def __init__(self):
        self.errors: list[ValidationError] = []
        self.warnings: list[ValidationError] = []
        self.stats: dict = {}

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def add_error(self, message, **kwargs):
        e = ValidationError('error', message, **kwargs)
        self.errors.append(e)

    def add_warning(self, message, **kwargs):
        w = ValidationError('warning', message, **kwargs)
        self.warnings.append(w)


def _collect_block_tags(node: TLVNode) -> set[str]:
    """Get set of direct child tags."""
    return {child.tag for child in node.children}


def _validate_header(header: TLVNode, result: ValidationResult):
    """Validate file header structure."""
    if header.tag != 'FF45':
        result.add_error(f"Expected header tag FF45, got {header.tag}", line=1, tag=header.tag)
        return

    # Must contain FF49
    ff49 = header.find_tag('FF49')
    if not ff49:
        result.add_error("Header missing FF49 (File Header Block)", line=1, tag='FF45')
        return

    # Check mandatory header fields
    for tag in HEADER_MANDATORY:
        if not ff49.find_tag(tag):
            result.add_error(
                f"Header block missing mandatory tag {tag} ({get_tag_name(tag)})",
                line=1, tag=tag
            )

    # Extract file type
    ftype_node = ff49.find_tag('DF807D')
    if ftype_node:
        ftype = ftype_node.value
        if ftype not in ('FTYPIIA', 'FTYPIMA', 'FTYPIRA'):
            result.add_warning(f"Unusual file type: '{ftype}'", line=1, tag='DF807D')


def _validate_trailer(trailer: TLVNode, expected_records: int, result: ValidationResult, line: int, btrt_types: list = None):
    """Validate file trailer structure."""
    if trailer.tag != 'FF46':
        result.add_error(f"Expected trailer tag FF46, got {trailer.tag}", line=line, tag=trailer.tag)
        return

    ff4a = trailer.find_tag('FF4A')
    if not ff4a:
        result.add_error("Trailer missing FF4A (File Trailer Block)", line=line, tag='FF46')
        return

    # Check record count
    rec_count_node = ff4a.find_tag('DF807E')
    if rec_count_node:
        try:
            declared = int(rec_count_node.value)
            # BTRT30 and BTRT51 files have declared count off by 1
            btrt_codes = [c for c, d in (btrt_types or [])]
            if any(c in ('BTRT30', 'BTRT51') for c in btrt_codes):
                declared -= 1
            if declared != expected_records:
                result.add_warning(
                    f"Trailer declares {declared} records but file contains {expected_records}",
                    line=line, tag='DF807E'
                )
        except ValueError:
            result.add_warning(
                f"Invalid record count value: '{rec_count_node.value}'",
                line=line, tag='DF807E'
            )


def _validate_record(record: TLVNode, result: ValidationResult):
    """Validate a data record against BTRT spec."""
    record_tag = record.tag.upper()

    # Check if known BTRT type
    if record_tag not in BTRT_TAG_MAP:
        result.add_error(
            f"Unknown record type tag: {record_tag}",
            line=record.line, tag=record_tag
        )
        return

    btrt_code, btrt_desc = BTRT_TAG_MAP[record_tag]

    # Check for empty record
    if not record.children:
        result.add_error(
            f"Record {btrt_code} is empty (no blocks/data)",
            line=record.line, tag=record_tag
        )
        return

    # Get expected blocks
    expected_blocks = BTRT_BLOCKS.get(record_tag, {})
    found_tags = _collect_block_tags(record)

    # Filter to just the block-level tags (FF?? tags, not DF?? sequence numbers)
    found_blocks = {t for t in found_tags if t.startswith('FF') and not t.startswith('FFFF')}

    # Check mandatory blocks present
    for block_tag, mandatory in expected_blocks.items():
        if mandatory == 'M' and block_tag not in found_blocks:
            result.add_error(
                f"{btrt_code}: Missing mandatory block {block_tag} ({get_tag_name(block_tag)})",
                line=record.line, tag=block_tag, block=record_tag
            )

    # Validate MAIN_BLOCK (FF2E) contents
    main_block = record.find_tag('FF2E')
    if main_block:
        _validate_main_block(main_block, btrt_code, result)

    # Validate each sub-block is not empty
    for child in record.children:
        if child.tag.startswith('FF') and not child.tag.startswith('FFFF'):
            if not child.children and not child.value:
                result.add_error(
                    f"{btrt_code}: Block {child.tag} ({get_tag_name(child.tag)}) is empty",
                    line=record.line, tag=child.tag, block=record_tag
                )

    # Validate nested structure of key blocks
    card_block = record.find_tag('FF24')
    if card_block:
        _validate_card_block(card_block, btrt_code, result)

    acct_block = record.find_tag('FF26')
    if acct_block:
        _validate_account_block(acct_block, btrt_code, result)

    cust_id_block = record.find_tag('FF2C')
    if cust_id_block:
        _validate_customer_id_block(cust_id_block, btrt_code, result)


def _validate_main_block(block: TLVNode, btrt_code: str, result: ValidationResult):
    """Validate MAIN_BLOCK contents."""
    # Check Application Type (DF8000) is present and matches
    app_type = block.find_tag('DF8000')
    if not app_type:
        result.add_error(
            f"{btrt_code}: MAIN_BLOCK missing DF8000 (Application Type)",
            line=block.line, tag='DF8000', block='FF2E'
        )
    else:
        val = app_type.value
        if not val.startswith('BTRT'):
            result.add_warning(
                f"{btrt_code}: Application Type value '{val}' doesn't start with 'BTRT'",
                line=block.line, tag='DF8000'
            )

    # Check Officer ID
    if not block.find_tag('DF803F'):
        result.add_error(
            f"{btrt_code}: MAIN_BLOCK missing DF803F (Officer ID)",
            line=block.line, tag='DF803F', block='FF2E'
        )


def _validate_card_block(block: TLVNode, btrt_code: str, result: ValidationResult):
    """Validate CARD_BLOCK (FF24) structure."""
    # Should contain FF33 (CARD_INIT) and/or FF34 (CARD_DATA)
    has_init = block.find_tag('FF33') is not None
    has_data = block.find_tag('FF34') is not None

    if not has_init and not has_data:
        if not block.children:
            result.add_error(
                f"{btrt_code}: CARD_BLOCK (FF24) is empty",
                line=block.line, tag='FF24'
            )


def _validate_account_block(block: TLVNode, btrt_code: str, result: ValidationResult):
    """Validate ACCOUNT_BLOCK (FF26) structure."""
    # Should contain FF36 (ACCOUNT_INIT)
    has_init = block.find_tag('FF36') is not None
    if not has_init and not block.children:
        result.add_error(
            f"{btrt_code}: ACCOUNT_BLOCK (FF26) is empty",
            line=block.line, tag='FF26'
        )

    # If FF36 exists, check mandatory account tags
    ff36 = block.find_tag('FF36')
    if ff36:
        for tag in ('DF8033', 'DF8035', 'DF8034'):
            if not ff36.find_tag(tag):
                result.add_warning(
                    f"{btrt_code}: ACCOUNT_INIT missing {tag} ({get_tag_name(tag)})",
                    line=block.line, tag=tag, block='FF36'
                )


def _validate_customer_id_block(block: TLVNode, btrt_code: str, result: ValidationResult):
    """Validate CUSTOMER_IDENTIFICATION_BLOCK (FF2C) structure."""
    # Should contain FF22 (PERSON) and/or FF2A (ADDRESS)
    has_person = block.find_tag('FF22') is not None
    has_address = block.find_tag('FF2A') is not None

    if not has_person and not has_address and not block.children:
        result.add_error(
            f"{btrt_code}: CUSTOMER_IDENTIFICATION_BLOCK (FF2C) is empty",
            line=block.line, tag='FF2C'
        )


def validate_file(content: str) -> ValidationResult:
    """Main validation entry point. Parses and validates an IIA/IMA file."""
    result = ValidationResult()

    # Parse the file
    parsed = parse_iia_file(content)

    # Collect parse errors
    for err in parsed['errors']:
        result.add_error(err['message'], line=err['line'], position=err['position'])

    # Collect parse warnings (e.g. block length mismatches)
    for warn in parsed.get('warnings', []):
        result.add_warning(warn['message'], line=warn['line'], position=warn['position'])

    if result.errors:
        # If we can't even parse, return early
        result.stats = {'parse_failed': True, 'line_count': parsed['line_count']}
        return result

    # Validate header
    if parsed['header']:
        _validate_header(parsed['header'], result)
        # Extract stats from header
        ff49 = parsed['header'].find_tag('FF49')
        if ff49:
            result.stats['file_type'] = ff49.get_value('DF807D') or 'Unknown'
            result.stats['file_date'] = ff49.get_value('DF807C') or 'Unknown'
            result.stats['institution'] = ff49.get_value('DF8079') or 'Unknown'
            result.stats['agent_code'] = ff49.get_value('DF807A') or 'Unknown'
    else:
        result.add_error("No file header found (FF45)")

    # Validate records
    num_records = len(parsed['records'])
    result.stats['record_count'] = num_records

    btrt_types = []
    for record in parsed['records']:
        _validate_record(record, result)
        tag = record.tag.upper()
        if tag in BTRT_TAG_MAP:
            code, desc = BTRT_TAG_MAP[tag]
            # Refine BTRT51/55 by checking DF8000
            if tag == 'FFFF0F':
                main = record.find_tag('FF2E')
                if main:
                    app_type_node = main.find_tag('DF8000')
                    if app_type_node:
                        code = app_type_node.value
                        desc = BTRT_TAG_MAP[tag][1]
            btrt_types.append((code, desc))

    result.stats['btrt_types'] = btrt_types

    # Validate trailer
    if parsed['trailer']:
        trailer_line = parsed['line_count']
        _validate_trailer(parsed['trailer'], num_records, result, trailer_line, btrt_types)
        ff4a = parsed['trailer'].find_tag('FF4A')
        if ff4a:
            result.stats['declared_records'] = ff4a.get_value('DF807E')
            result.stats['crc'] = ff4a.get_value('DF8060')
    else:
        result.add_error("No file trailer found (FF46)")

    result.stats['line_count'] = parsed['line_count']
    result.stats['file_size'] = len(content)

    return result


def build_tree_display(node: TLVNode, depth: int = 0) -> list[dict]:
    """Build a flat list of dicts for tree display."""
    rows = []
    indent = "  " * depth
    name = get_tag_name(node.tag)
    if node.children:
        rows.append({
            'indent': depth,
            'tag': node.tag,
            'name': name,
            'value': f'({len(node.children)} children)',
            'pos': f'{node.start_pos}-{node.end_pos}',
        })
        for child in node.children:
            rows.extend(build_tree_display(child, depth + 1))
    else:
        val_display = node.value if len(node.value) <= 50 else node.value[:47] + '...'
        rows.append({
            'indent': depth,
            'tag': node.tag,
            'name': name,
            'value': val_display,
            'pos': f'{node.start_pos}-{node.end_pos}',
        })
    return rows
