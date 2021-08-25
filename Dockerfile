FROM openjdk:11

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
ADD . /app

# run the command to start uWSGI
CMD ["java", "-jar","-Dspring.datasource.url=jdbc:postgresql://192.168.0.199:5432/test","templatesecurity/target/templatesecurity-0.0.1-SNAPSHOT.war"]




