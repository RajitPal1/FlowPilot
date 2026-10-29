require("dotenv").config();

if(!process.env.MONGO_URI){
    console.log("MONGO_URI is declared as a environmental variable");
}

if(!process.env.JWT_SECRET){
    console.log("JWT_SECRET is declared as a environmental variable");
}

if(!process.env.GOOGLE_CLIENT_ID){
    console.log("GOOGLE_CLIENT_ID is declared as a environmental variable");
}

if(!process.env.GOOGLE_CLIENT_SECRET){
    console.log("GOOGLE_CLIENT_SECRET is declared as a environmental variable");
}

if(!process.env.GOOGLE_REFRESH_TOKEN){
    console.log("GOOGLE_REFRESH_TOKEN is declared as a environmental variable");
}

if(!process.env.GOOGLE_USER){
    console.log("GOOGLE_USER is declared as a environmental variable");
}

const config = {
    MONGO_URI:process.env.MONGO_URI,
    GOOGLE_CLIENT_ID:process.env.GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET:process.env.GOOGLE_CLIENT_SECRET,
    GOOGLE_REFRESH_TOKEN:process.env.GOOGLE_REFRESH_TOKEN,
    GOOGLE_USER:process.env.GOOGLE_USER,
    JWT_SECRET:process.env.JWT_SECRET,
}

module.exports = config;