async function uploadFile() {

  const fileInput = document.getElementById("fileInput");
  const formData = new FormData();

  formData.append("media", fileInput.files[0]);

  const response = await fetch("/analyze", {
    method: "POST",
    body: formData
  });

  const data = await response.json();

  document.getElementById("result").innerHTML = `
    <h2>AI Probability: ${data.probability}%</h2>
    <h2>Trust Score: ${data.trustScore}</h2>
    <p>${data.explanation}</p>
  `;
}