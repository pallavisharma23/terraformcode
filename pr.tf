# configure the provider
provider "aws" {
  region = "ap-south-1"
  profile = "pallavis"
}
# creating a key pair
resource "tls_private_key" "keypallavi" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
resource "aws_key_pair" "authorized_keys" {
  key_name   = "authorized_keys"
  public_key = tls_private_key.keypallavi.public_key_openssh
}
# saving key to local file
resource "local_file" "authorized_keys" {
    content  = tls_private_key.keypallavi.private_key_pem
    filename = "/root/keypallavi.pem"
}
# creating a SG
resource "aws_security_group" "allow_ssh_http_ru" {
  name        = "allow_ssh_http_ru"
  description = "Allow TLS ssh and http inbound traffic"
  vpc_id = "vpc-70bda018"

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "http"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "allow_ssh_http_ru"
  }
}
# launching an ec2 instance
resource "aws_instance" "terrainsta_ec2" {
  ami  = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name = aws_key_pair.authorized_keys.key_name
  security_groups = [ "allow_ssh_http_ru"]

  depends_on = [
    null_resource.nulllocal3,
  ]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = file("/root/keypallavi.pem")
    host     = aws_instance.terrainsta_ec2.public_ip
  }
  provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd ;php ;git ;wget -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd",
      "sudo yum install java-1.8.0-openjdk-devel -y",
      "sudo wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat/jenkins.repo",
      "sudo rpm --import https://pkg.jenkins.io/redhat/jenkins.io.key",
      "sudo yum install jenkins -y",
    ]
  }
  tags = {
    Name = "terrform-os2"
  }
}
# create an ebs volume
resource "aws_ebs_volume" "terraebsV" {
  availability_zone = aws_instance.terrainsta_ec2.availability_zone
  size              = 1
  tags = {
    Name = "ebsvolume"
  }
}
# create an ebs snapshot
resource "aws_ebs_snapshot" "terraebsV_snapshot" {
  volume_id = aws_ebs_volume.terraebsV.id
  tags = {
    Name = "ebsvol_snap"
  }
}
# attaching the volume
resource "aws_volume_attachment" "ebsvolV-attach" {
  device_name = "/dev/sde"
  volume_id   = aws_ebs_volume.terraebsV.id
  instance_id = aws_instance.terrainsta_ec2.id
  force_detach = true
}
resource "null_resource" "nullremote2"  {
  depends_on = [
    aws_volume_attachment.ebsvolV-attach,
    aws_s3_bucket_object.objects
  ]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = file("/root/keypallavi.pem")
    host     = aws_instance.terrainsta_ec2.public_ip
  }
  provisioner "remote-exec" {
    inline = [
      "sudo mkfs.ext4  /dev/xvde",
      "sudo mount  /dev/xvde  /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/pallavisharma23/terraformcode/tree/master /var/www/html"
    ]
  }
}
# setting read_permission on pem
resource "null_resource" "nulllocal3"  {
  depends_on = [
    local_file.authorized_keys,
  ]
   provisioner "local-exec" {
            command = "chmod 600 /root/keypallavi.pem"
        }
}
resource "aws_s3_bucket" "bu" {
  bucket = "terraformbu123"
  acl    = "public-read"
  tags = {
    Name        = "terraformbu123"
  }
}
resource "aws_s3_bucket_object" "objects" {
  depends_on = [ aws_s3_bucket.bu, ]
  bucket = "terraformbu123"
  key    = "linux-wallpaper-1366x768.jpg"
  source = "/root/linux-wallpaper-1366x768.jpg"
  acl = "public-read"
}
locals {
  s3_origin_ids = "S3-terraformbu123"
}
# origin access id
resource "aws_cloudfront_origin_access_identity" "oriacessidents" {
  comment = "this is OAI to be used in cloudfront"
}
# creating cloudfront
resource "aws_cloudfront_distribution" "s3_distribution1" {
  depends_on = [ aws_cloudfront_origin_access_identity.oriacessidents,
                 null_resource.nullremote2,
  ]
  origin {
    domain_name = aws_s3_bucket.bu.bucket_domain_name
    origin_id   = local.s3_origin_ids
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.oriacessidents.cloudfront_access_identity_path
    }
  }
    connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = file("/root/keypallavi.pem")
    host     = aws_instance.terrainsta_ec2.public_ip
  }
  provisioner "remote-exec" {
    inline = [
      "sudo su << EOF",
      "echo \"<img src='http://${self.domain_name}/${aws_s3_bucket_object.objects.key}'>\" >> /var/www/html/index.html",
      "EOF"
    ]
  }
  enabled             = true
  is_ipv6_enabled     = true
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_ids
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    viewer_protocol_policy = "redirect-to-https"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
