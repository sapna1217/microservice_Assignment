# 1. Start from Node.js image
FROM node:18

# 2. Set the app directory in the container
WORKDIR /app

# 3. Copy only package.json files first (to install faster later)
COPY package*.json ./

# 4. Install Node dependencies
RUN npm install

# 5. Copy the rest of your code into the container
COPY . .

# 6. Expose port 5000 (so we can access it from outside)
EXPOSE 5000

# 7. Run the app
CMD ["node", "src/index.js"]
