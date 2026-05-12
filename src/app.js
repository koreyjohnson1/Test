const express = require("express");
const requireAuth = require("./middleware/requireAuth");
const requireScopes = require("./middleware/requireScopes");
const {
  listDocumentsForOwner,
  getDocumentById,
  createDocument,
  deleteDocument,
} = require("./data");

const ROLES_CLAIM = "https://example.com/roles";

function hasRole(auth, role) {
  const roles = auth && auth[ROLES_CLAIM];
  return Array.isArray(roles) && roles.includes(role);
}

function ownsDocument(auth, document) {
  return document.ownerSub === auth.sub;
}

function createApp(authOptions = {}) {
  const app = express();

  app.use(express.json());

  app.get("/api/documents", requireAuth(authOptions), (req, res) => {
    const documents = listDocumentsForOwner(req.auth.sub);
    return res.json({ documents });
  });

  app.get("/api/documents/:id", requireAuth(authOptions), (req, res) => {
    const document = getDocumentById(req.params.id);

    if (!document) {
      return res.status(404).json({ error: "not_found" });
    }

    if (!ownsDocument(req.auth, document) && !hasRole(req.auth, "auditor")) {
      return res.status(403).json({ error: "forbidden" });
    }

    return res.json({ document });
  });

  app.post(
    "/api/documents",
    requireAuth(authOptions),
    requireScopes("documents:write"),
    (req, res) => {
      const document = createDocument({
        ownerSub: req.auth.sub,
        title: req.body.title || "Untitled",
        body: req.body.body || "",
      });

      return res.status(201).json({ document });
    }
  );

  app.delete("/api/documents/:id", requireAuth(authOptions), (req, res) => {
    const document = getDocumentById(req.params.id);

    if (!document) {
      return res.status(404).json({ error: "not_found" });
    }

    if (!ownsDocument(req.auth, document)) {
      return res.status(403).json({ error: "forbidden" });
    }

    deleteDocument(document.id);
    return res.status(204).send();
  });

  return app;
}

module.exports = createApp;