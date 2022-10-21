# The base go-image
FROM golang:1.19-alpine
 
# Create a directory for the app
RUN mkdir /app
 
# Copy all files from the current directory to the app directory
COPY . /app
 
# Set working directory
WORKDIR /app
 
ENV UNIFI_USER=""
ENV UNIFI_PASS=""
ENV UNIFI_HOST=""

EXPOSE 8080

# Run command as described:
# go build will build an executable file named server in the current directory
RUN GOOS=linux GOARCH=amd64 go build -o server . 

# Run the server executable
CMD [ "/app/server", "--insecure", "--port=8080" ]
