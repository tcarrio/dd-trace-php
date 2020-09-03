#include "ddtrace8/integration.hh"

namespace std {

size_t std::hash<integration>::operator()(const integration &that) const noexcept { return 0; }

size_t std::hash<integration_function>::operator()(const integration_function &that) const
    noexcept {
    return 0;
}

size_t std::hash<integration_class>::operator()(const integration_class &that) const noexcept {
    return 0;
}
}  // namespace std

bool integration_function::operator==(const integration_function &that) const noexcept {
    // we trust the lc_name
    return lc_name == that.lc_name;
}

bool integration_class::operator==(const integration_class &that) const noexcept {
    // we trust the lc_name
    return lc_name == that.lc_name;
}

bool integration::operator==(const integration &that) const noexcept {
    // we trust the lc_name
    return lc_name == that.lc_name;
}
