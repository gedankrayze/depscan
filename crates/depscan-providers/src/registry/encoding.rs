use super::*;

pub(crate) fn encode_path_segment(segment: &str) -> PercentEncode<'_> {
    utf8_percent_encode(segment, RFC3986_PATH_SEGMENT_ENCODE_SET)
}
