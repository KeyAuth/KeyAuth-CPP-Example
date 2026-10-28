#pragma once
#include "auth.hpp"

inline bool checkAuthenticated(KeyAuth::api& app) {
    app.check();
    return app.response.success && app.authenticated();
}
