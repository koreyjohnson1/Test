function initialDocuments() {
  return [
    {
      id: "doc_1",
      ownerSub: "user_123",
      title: "User 123 private document",
      body: "Owned by user_123",
    },
    {
      id: "doc_2",
      ownerSub: "user_456",
      title: "User 456 private document",
      body: "Owned by user_456",
    },
  ];
}

let documents = initialDocuments();

function listDocumentsForOwner(ownerSub) {
  return documents.filter((document) => document.ownerSub === ownerSub);
}

function getDocumentById(id) {
  return documents.find((document) => document.id === id) || null;
}

function createDocument({ ownerSub, title, body }) {
  const document = {
    id: `doc_${documents.length + 1}`,
    ownerSub,
    title,
    body,
  };

  documents.push(document);
  return document;
}

function deleteDocument(id) {
  const index = documents.findIndex((document) => document.id === id);

  if (index === -1) {
    return false;
  }

  documents.splice(index, 1);
  return true;
}

function resetDocuments() {
  documents = initialDocuments();
}

module.exports = {
  listDocumentsForOwner,
  getDocumentById,
  createDocument,
  deleteDocument,
  resetDocuments,
};