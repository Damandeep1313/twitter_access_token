# Step 1: Use an official Node.js image as a base
FROM node:18

# Step 2: Set the working directory
WORKDIR /app

# Step 3: Copy the package.json and package-lock.json files to the working directory
COPY package*.json ./

# Step 4: Install dependencies
RUN npm install

# Step 5: Copy the rest of the application code to the working directory
COPY . .

# Step 6: Expose the port the app runs on
EXPOSE 3000

# Step 7: Set environment variables (optional if using dotenv for local development)
# ENV PORT=3000
# ENV CLIENT_ID=your_client_id
# ENV CLIENT_SECRET=your_client_secret

# Step 8: Start the application with server1.js
CMD ["node", "server.js"]
