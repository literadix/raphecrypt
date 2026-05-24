//! Defensive inspection for non-visible Unicode characters.

use std::fmt::Write;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanFinding {
    pub char_index: usize,
    pub byte_index: usize,
    pub codepoint: u32,
    pub name: &'static str,
    pub category: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    pub total_chars: usize,
    pub total_bytes: usize,
    pub findings: Vec<ScanFinding>,
}

impl ScanReport {
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }
}

pub fn scan_text(input: &str) -> ScanReport {
    let findings = input
        .char_indices()
        .enumerate()
        .filter_map(|(char_index, (byte_index, character))| {
            classify_non_visible(character).map(|(category, name)| ScanFinding {
                char_index,
                byte_index,
                codepoint: character as u32,
                name,
                category,
            })
        })
        .collect();

    ScanReport {
        total_chars: input.chars().count(),
        total_bytes: input.len(),
        findings,
    }
}

pub fn format_scan_report(report: &ScanReport) -> String {
    let mut output = String::new();

    writeln!(output, "Scan report").unwrap();
    writeln!(output, "Characters: {}", report.total_chars).unwrap();
    writeln!(output, "Bytes: {}", report.total_bytes).unwrap();
    writeln!(output, "Findings: {}", report.findings.len()).unwrap();

    if report.findings.is_empty() {
        writeln!(output, "No non-visible Unicode characters found.").unwrap();
        return output;
    }

    writeln!(output).unwrap();
    writeln!(
        output,
        "{:<10} {:<10} {:<12} {:<18} Name",
        "Char", "Byte", "Codepoint", "Category"
    )
    .unwrap();

    for finding in &report.findings {
        writeln!(
            output,
            "{:<10} {:<10} U+{:<9X} {:<18} {}",
            finding.char_index,
            finding.byte_index,
            finding.codepoint,
            finding.category,
            finding.name
        )
        .unwrap();
    }

    output
}

fn classify_non_visible(character: char) -> Option<(&'static str, &'static str)> {
    if matches!(character, '\n' | '\r' | '\t' | ' ') {
        return None;
    }

    if is_unicode_tag_character(character) {
        return Some(("Format", "Unicode tag character"));
    }

    match character {
        '\u{00AD}' => Some(("Format", "Soft hyphen")),
        '\u{034F}' => Some(("Format", "Combining grapheme joiner")),
        '\u{061C}' => Some(("Format", "Arabic letter mark")),
        '\u{070F}' => Some(("Format", "Syriac abbreviation mark")),
        '\u{180E}' => Some(("Format", "Mongolian vowel separator")),
        '\u{200B}' => Some(("Format", "Zero width space")),
        '\u{200C}' => Some(("Format", "Zero width non-joiner")),
        '\u{200D}' => Some(("Format", "Zero width joiner")),
        '\u{200E}' => Some(("Format", "Left-to-right mark")),
        '\u{200F}' => Some(("Format", "Right-to-left mark")),
        '\u{202A}' => Some(("Format", "Left-to-right embedding")),
        '\u{202B}' => Some(("Format", "Right-to-left embedding")),
        '\u{202C}' => Some(("Format", "Pop directional formatting")),
        '\u{202D}' => Some(("Format", "Left-to-right override")),
        '\u{202E}' => Some(("Format", "Right-to-left override")),
        '\u{2060}' => Some(("Format", "Word joiner")),
        '\u{2061}' => Some(("Format", "Function application")),
        '\u{2062}' => Some(("Format", "Invisible times")),
        '\u{2063}' => Some(("Format", "Invisible separator")),
        '\u{2064}' => Some(("Format", "Invisible plus")),
        '\u{2066}' => Some(("Format", "Left-to-right isolate")),
        '\u{2067}' => Some(("Format", "Right-to-left isolate")),
        '\u{2068}' => Some(("Format", "First strong isolate")),
        '\u{2069}' => Some(("Format", "Pop directional isolate")),
        '\u{206A}'..='\u{206F}' => Some(("Format", "Deprecated format character")),
        '\u{FEFF}' => Some(("Format", "Byte order mark")),
        '\u{FFF9}'..='\u{FFFB}' => Some(("Format", "Interlinear annotation character")),
        '\u{1BCA0}'..='\u{1BCA3}' => Some(("Format", "Shorthand format character")),
        '\u{1D173}'..='\u{1D17A}' => Some(("Format", "Musical format character")),
        '\u{E000}'..='\u{F8FF}' => Some(("Private Use", "Private-use character")),
        '\u{F0000}'..='\u{FFFFD}' => Some(("Private Use", "Supplementary private-use character")),
        '\u{100000}'..='\u{10FFFD}' => Some(("Private Use", "Supplementary private-use character")),
        _ if character.is_control() => Some(("Control", "Control character")),
        _ if is_non_ascii_whitespace(character) => Some(("Separator", "Non-ASCII whitespace")),
        _ => None,
    }
}

fn is_unicode_tag_character(character: char) -> bool {
    matches!(character, '\u{E0001}' | '\u{E0020}'..='\u{E007F}')
}

fn is_non_ascii_whitespace(character: char) -> bool {
    character.is_whitespace() && !matches!(character, '\n' | '\r' | '\t' | ' ')
}

#[cfg(test)]
mod tests {
    use super::{format_scan_report, scan_text};

    #[test]
    fn clean_visible_text_has_no_findings() {
        let report = scan_text("Hello café 東京 🔐\n\t");

        assert!(!report.has_findings());
    }

    #[test]
    fn detects_zero_width_and_tag_characters() {
        let report = scan_text("A\u{200B}B\u{E0001}C");

        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].codepoint, 0x200B);
        assert_eq!(report.findings[0].name, "Zero width space");
        assert_eq!(report.findings[1].codepoint, 0xE0001);
        assert_eq!(report.findings[1].name, "Unicode tag character");
    }

    #[test]
    fn detects_bidi_override_and_non_ascii_whitespace() {
        let report = scan_text("A\u{202E}B\u{00A0}C");

        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].name, "Right-to-left override");
        assert_eq!(report.findings[1].category, "Separator");
    }

    #[test]
    fn formats_clean_report() {
        let report = scan_text("Hello");
        let formatted = format_scan_report(&report);

        assert!(formatted.contains("Findings: 0"));
        assert!(formatted.contains("No non-visible Unicode characters found."));
    }

    #[test]
    fn formats_finding_report() {
        let report = scan_text("A\u{200B}B");
        let formatted = format_scan_report(&report);

        assert!(formatted.contains("Findings: 1"));
        assert!(formatted.contains("U+200B"));
        assert!(formatted.contains("Zero width space"));
    }
}
