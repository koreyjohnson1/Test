jest.mock("../src/jwt/validateToken", () => jest.fn());

const request = require("supertest");
const validateToken = require("../src/jwt/validateToken");
const createApp = require("../src/app");
const { resetDocuments } = require("../src/data");

const ROLES_CLAIM = "https://example.com/roles";

function userPayload(overrides = {}) {
  return {
    sub: "user_123",
    iss: "https://auth.example.com/",
    aud: "https://api.example.com",
    exp: Math.floor(Date.now() / 1000) + 300,
    scope: "documents:read documents:write",
    [ROLES_CLAIM]: [],
    ...overrides,
  };
}

describe("authorization middleware and document routes", () => {
  let app;

  beforeEach(() => {
    jest.clearAllMocks();
    resetDocuments();

    app = createApp({
      jwksUri: "https://auth.example.com/.well-known/jwks.json",
      issuer: "https://auth.example.com/",
      audience: "https://api.example.com",
    });
  });

  test("returns 401 when Authorization header is missing", async () => {
    const response = await request(app).get("/api/documents");

    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: "missing_token" });
  });

  test("returns safe 401 response when token validation fails", async () => {
    const error = new Error("expired");
    error.name = "TokenExpiredError";
    validateToken.mockRejectedValue(error);

    const response = await request(app)
      .get("/api/documents")
      .set("Authorization", "Bearer bad-token");

    expect(response.status).toBe(401);
    expect(response.body).toEqual({
      error: "invalid_token",
      reason: "TokenExpiredError",
    });
  });

  test("GET /api/documents returns only documents owned by authenticated user", async () => {
    validateToken.mockResolvedValue(userPayload({ sub: "user_123" }));

    const response = await request(app)
      .get("/api/documents")
      .set("Authorization", "Bearer valid-token");

    expect(response.status).toBe(200);
    expect(response.body.documents).toHaveLength(1);
    expect(response.body.documents[0].ownerSub).toBe("user_123");
  });

  test("GET /api/documents/:id allows owner", async () => {
    validateToken.mockResolvedValue(userPayload({ sub: "user_123" }));

    const response = await request(app)
      .get("/api/documents/doc_1")
      .set("Authorization", "Bearer valid-token");

    expect(response.status).toBe(200);
    expect(response.body.document.id).toBe("doc_1");
  });

  test("GET /api/documents/:id allows auditor even when not owner", async () => {
    validateToken.mockResolvedValue(
      userPayload({
        sub: "auditor_user",
        [ROLES_CLAIM]: ["auditor"],
      })
    );

    const response = await request(app)
      .get("/api/documents/doc_1")
      .set("Authorization", "Bearer valid-token");

    expect(response.status).toBe(200);
    expect(response.body.document.id).toBe("doc_1");
  });

  test("GET /api/documents/:id denies non-owner without auditor role", async () => {
    validateToken.mockResolvedValue(userPayload({ sub: "user_999" }));

    const response = await request(app)
      .get("/api/documents/doc_1")
      .set("Authorization", "Bearer valid-token");

    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: "forbidden" });
  });

  test("POST /api/documents requires documents:write scope", async () => {
    validateToken.mockResolvedValue(
      userPayload({
        scope: "documents:read",
      })
    );

    const response = await request(app)
      .post("/api/documents")
      .set("Authorization", "Bearer valid-token")
      .send({
        title: "New document",
        body: "New body",
      });

    expect(response.status).toBe(403);
    expect(response.body.error).toBe("insufficient_scope");
  });

  test("POST /api/documents creates document owned by authenticated user", async () => {
    validateToken.mockResolvedValue(userPayload({ sub: "user_123" }));

    const response = await request(app)
      .post("/api/documents")
      .set("Authorization", "Bearer valid-token")
      .send({
        title: "New document",
        body: "New body",
      });

    expect(response.status).toBe(201);
    expect(response.body.document.ownerSub).toBe("user_123");
    expect(response.body.document.title).toBe("New document");
  });

  test("DELETE /api/documents/:id allows owner", async () => {
    validateToken.mockResolvedValue(userPayload({ sub: "user_123" }));

    const response = await request(app)
      .delete("/api/documents/doc_1")
      .set("Authorization", "Bearer valid-token");

    expect(response.status).toBe(204);
  });

  test("DELETE /api/documents/:id denies auditor who is not owner", async () => {
    validateToken.mockResolvedValue(
      userPayload({
        sub: "auditor_user",
        [ROLES_CLAIM]: ["auditor"],
      })
    );

    const response = await request(app)
      .delete("/api/documents/doc_1")
      .set("Authorization", "Bearer valid-token");

    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: "forbidden" });
  });
});