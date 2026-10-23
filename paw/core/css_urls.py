"""Literal CSS url(...) boundaries for bounded supplied HTML, without rendering.

Only literal function names/arguments are interpreted. CSS escapes are traversed
for boundaries but never decoded into network destinations. Other lexical text
keeps its existing candidate extraction; this is not a full CSS resource parser.
"""

_SPACE = ' \t\r\n\f'
_HEX = '0123456789abcdefABCDEF'


def _escape_end(text, position):
    """Skip one CSS escape, preserving its original spelling."""
    position += 1
    if position == len(text): return position
    if text[position] in _HEX:
        end = position
        while end < len(text) and end-position < 6 and text[end] in _HEX: end += 1
        if end < len(text) and text[end] in _SPACE:
            end += 2 if text[end:end+2] == '\r\n' else 1
        return end
    return position + (2 if text[position:position+2] == '\r\n' else 1)


def _string_end(text, position):
    quote = text[position]
    position += 1
    while position < len(text):
        char = text[position]
        if char == quote: return position+1, True
        if char in '\r\n\f': return position, False
        position = _escape_end(text,position) if char == '\\' else position+1
    return position, False


def _remnant_end(text, position):
    # CSS bad-url recovery stops at the first unescaped close parenthesis.
    while position < len(text):
        if text[position] == ')': return position+1
        position = _escape_end(text,position) if text[position] == '\\' else position+1
    return position


def _function_end(text, position):
    """Bound a quoted function, including unsupported nested component values.

    Unlike unquoted bad-url tokens, quoted functions contain strings/comments
    and balanced simple blocks. Their internal ')' must not truncate evidence.
    """
    stack = [')']
    closers = {'(':')', '[':']', '{':'}'}
    while position < len(text):
        char = text[position]
        if text.startswith('/*',position):
            end = text.find('*/',position+2)
            if end == -1: return len(text)
            position = end+2
        elif char in '\"\'':
            position, _ = _string_end(text,position)
        elif char in '#@':
            position = _name_end(text,position+1)
        elif _name_char(char):
            start = position
            position = _name_end(text,position)
            if position == start:
                position += 1
                continue
            if text[start:position].lower() == 'url' and text[position:position+1] == '(':
                argument = position+1
                while argument < len(text) and text[argument] in _SPACE: argument += 1
                if argument == len(text) or text[argument] not in '\"\'':
                    # A URL/bad-URL token owns its punctuation, including '['
                    # and '/*'. Do not interpret it as component block syntax.
                    position, _, _, _ = _unquoted_argument(text,argument)
        elif char in closers:
            stack.append(closers[char]); position += 1
        elif char == stack[-1]:
            stack.pop(); position += 1
            if not stack: return position
        else:
            position += 1
    return position


def _argument(text, position):
    """Return expression end, argument, validity and quoted separator text."""
    while position < len(text) and text[position] in _SPACE: position += 1
    start = position
    if position < len(text) and text[position] in '\"\'':
        end, closed = _string_end(text,position)
        position = end
        while position < len(text):
            if text[position] in _SPACE:
                position += 1
            elif text.startswith('/*',position):
                comment = text.find('*/',position+2)
                if comment == -1: return len(text), None, False, ''
                position = comment+2
            else:
                break
        if closed and position < len(text) and text[position] == ')':
            return position+1, text[start+1:end-1], True, text[end:position]
        return _function_end(text,start), None, False, ''
    return _unquoted_argument(text,position)


def _unquoted_argument(text, position):
    """Consume one URL/bad-URL token from its first non-whitespace character."""
    start = position
    while position < len(text):
        char = text[position]
        if char == ')': return position+1, text[start:position], True, ''
        if char in _SPACE:
            end = position
            while position < len(text) and text[position] in _SPACE: position += 1
            if position < len(text) and text[position] == ')':
                return position+1, text[start:end], True, ''
            return _remnant_end(text,position), None, False, ''
        if char in '\"\'(' or ord(char) < 32 or ord(char) == 127:
            return _remnant_end(text,position), None, False, ''
        if char == '\\':
            if position+1 == len(text) or text[position+1] in '\r\n\f':
                return _remnant_end(text,position), None, False, ''
            position = _escape_end(text,position)
        else:
            position += 1
    return position, None, False, ''


def _name_char(char):
    return char.isalnum() or char in '_-\\' or ord(char) >= 128


def _name_end(text, position):
    while position < len(text) and _name_char(text[position]):
        if text[position] == '\\':
            if position+1 < len(text) and text[position+1] in '\r\n\f': break
            position = _escape_end(text,position)
        else:
            position += 1
    return position


def extract_css_url_candidates(text, extractor):
    """Use whole url() arguments, never embedded HTTP parts of data/relative URLs.

    Malformed expressions containing recognized candidates are retained whole as
    non-URL textual evidence, so a valid-looking prefix cannot become a target.
    Comments, ordinary strings, other functions and text retain lexical behavior.
    The iterative scanner consumes each bounded HTML text once, without recursion.
    """
    candidates, position, pending = [], 0, 0
    while position < len(text):
        char = text[position]
        if text.startswith('/*',position):
            end = text.find('*/',position+2)
            position = len(text) if end == -1 else end+2
        elif char in '\"\'':
            position, _ = _string_end(text,position)
        elif char in '#@':
            # Hash/at-keyword names are not function names. Leave their block
            # contents and any actual nested url() tokens to the main scanner.
            position = _name_end(text,position+1)
        elif _name_char(char):
            start = position
            position = _name_end(text,position)
            if position == start:
                position += 1
                continue
            if text[start:position].lower() != 'url' or text[position:position+1] != '(':
                continue
            candidates.extend(extractor(text[pending:start]))
            position, argument, valid, trivia = _argument(text,position+1)
            if valid:
                if any(argument.startswith(value) for value in extractor(argument)):
                    candidates.append(argument)
                if extractor(trivia):
                    # Preserve complete comment/whitespace separators as
                    # textual evidence, never promote an inner HTTP mention.
                    candidates.append(trivia)
            else:
                expression = text[start:position]
                if extractor(expression): candidates.append(expression)
            pending = position
        else:
            position += 1
    candidates.extend(extractor(text[pending:]))
    return list(dict.fromkeys(candidates))
