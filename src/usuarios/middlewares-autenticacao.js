const passport = require("passport");
module.exports = {
  local: (req, res, next) => {
    passport.authenticate(
      "local",
      { session: false },
      (error, usuario, info) => {
        if (error && error.name === "InvalidArgumentError") {
          return res.status(401).json({ error: error.message });
        }

        if (error) {
          return res.status(500).json({ error: error.message });
        }

        if (!usuario) {
          res.status(401).json();
        }

        req.user = usuario;
        return next();
      }
    )(req, res, next);
  },
  bearer: (req, res, next) => {
    passport.authenticate(
      "bearer",
      { session: false },
      (error, usuario, info) => {
        if (error && error.name === "JsonWebTokenError") {
          return res.status(401).json({ error: error.message });
        }

        if (error) {
          res.status(500).json({ error: error.message });
        }

        if (!usuario) {
          res.status(401).json();
        }

        req.user = usuario;
        return next();
      }
    )(req, res, next);
  },
};
