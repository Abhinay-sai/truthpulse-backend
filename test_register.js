const axios = require('axios');

async function testVerify() {
  console.log("Testing truthpulse-backend.onrender.com verification endpoint...");
  try {
    const res = await axios.post('https://truthpulse-backend.onrender.com/auth/verify-email', {
      email: 'test@example.com',
      otp: '123456'
    });
    console.log("Status:", res.status);
    console.log("Data:", res.data);
  } catch (err) {
    if (err.response) {
      console.log("Status:", err.response.status);
      console.log("Error Data:", err.response.data);
    } else {
      console.log("Network Error:", err.message);
    }
  }
}

testVerify();
