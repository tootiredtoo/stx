#ifndef SOCKET_HPP
#define SOCKET_HPP

#include <asio.hpp>

class ISocket {
 public:
  virtual ~ISocket() = default;

  virtual bool is_open() const = 0;
  virtual void close() = 0;
  virtual void close(asio::error_code& ec) = 0;
  virtual void async_send(const asio::const_buffer& buffer,
                          std::function<void(const asio::error_code&, std::size_t)> handler) = 0;
  virtual void async_receive(asio::mutable_buffer buffer,
                             std::function<void(const asio::error_code&, std::size_t)> handler) = 0;
  virtual std::size_t send(const asio::const_buffer& buffer) = 0;
  virtual std::size_t receive(asio::mutable_buffer buffer) = 0;
  virtual void shutdown(asio::ip::tcp::socket::shutdown_type what, asio::error_code& ec) = 0;
  virtual std::size_t read_some(asio::mutable_buffer buffer, asio::error_code& ec) = 0;
};

class AsioSocket : public ISocket {
 public:
  explicit AsioSocket(std::shared_ptr<asio::ip::tcp::socket> socket) : socket_(std::move(socket)) {}

  bool is_open() const override { return socket_->is_open(); }

  void close() override { socket_->close(); }

  void close(asio::error_code& ec) override { socket_->close(ec); }

  void async_send(const asio::const_buffer& buffer,
                  std::function<void(const asio::error_code&, std::size_t)> handler) override {
    asio::async_write(*socket_, buffer, handler);
  }

  void async_receive(asio::mutable_buffer buffer,
                     std::function<void(const asio::error_code&, std::size_t)> handler) override {
    asio::async_read(*socket_, buffer, handler);
  }

  std::size_t send(const asio::const_buffer& buffer) override { return socket_->send(buffer); }

  std::size_t receive(asio::mutable_buffer buffer) override { return socket_->receive(buffer); }

  void shutdown(asio::ip::tcp::socket::shutdown_type what, asio::error_code& ec) override {
    socket_->shutdown(what, ec);
  }

  std::size_t read_some(asio::mutable_buffer buffer, asio::error_code& ec) {
    return socket_->read_some(buffer, ec);
  }

  std::size_t write_some(asio::const_buffer buffer, asio::error_code& ec) {
    return socket_->write_some(buffer, ec);
  }

 private:
  std::shared_ptr<asio::ip::tcp::socket> socket_;
};

#endif  // SOCKET_HPP